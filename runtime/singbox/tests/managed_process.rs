#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use flowprobe_config_compiler::{
    ConfigCompiler, RuntimeConfigValidator, RuntimeOverlay, RuntimeValidationFailure, SystemBase,
    UserProfile,
};
use flowprobe_runtime_api::{
    CompiledConfig, NetworkRuntime, ProxyGroupId, ProxyId, RuntimeCapability, RuntimeError,
    RuntimeHealth, RuntimeOperation, RuntimePhase, RuntimeState, RuntimeUnavailableReason,
};
use flowprobe_singbox_runtime::{SingBoxOptions, SingBoxRuntime};
use nix::{
    errno::Errno,
    sys::signal::{kill, killpg},
    unistd::Pid,
};

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);
const FAKE_EXECUTABLE: &[u8] = include_bytes!("fixtures/fake-sing-box.sh");

struct AcceptConfig;

impl RuntimeConfigValidator for AcceptConfig {
    fn validate(&self, _canonical_runtime_json: &str) -> Result<(), RuntimeValidationFailure> {
        Ok(())
    }
}

struct TestDirectory {
    root: PathBuf,
    executable: PathBuf,
    state_directory: PathBuf,
}

struct ProcessGroupCleanup {
    process_group_id: i32,
    armed: bool,
}

impl ProcessGroupCleanup {
    fn new(process_group_id: i32) -> Self {
        Self {
            process_group_id,
            armed: true,
        }
    }

    fn confirm_gone(mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGroupCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _cleanup_result = killpg(
                Pid::from_raw(self.process_group_id),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
}

impl TestDirectory {
    fn new(behavior: &str) -> Self {
        let unique = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "flowprobe-singbox-runtime-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("unique test root should be created");
        let executable = root.join("fake-sing-box");
        fs::write(&executable, FAKE_EXECUTABLE).expect("fake executable should be written");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("fake executable should be private and executable");
        fs::write(root.join("behavior"), behavior).expect("behavior should be written");

        Self {
            state_directory: root.join("state dir; literal"),
            executable,
            root,
        }
    }

    fn options(&self) -> SingBoxOptions {
        SingBoxOptions {
            executable: self.executable.clone(),
            state_directory: self.state_directory.clone(),
            command_timeout: Duration::from_millis(500),
            startup_probe_duration: Duration::from_millis(500),
            stop_timeout: Duration::from_millis(100),
            max_config_bytes: 1024 * 1024,
            max_version_output_bytes: 1_024,
        }
    }

    fn runtime_config_files(&self) -> Vec<PathBuf> {
        match fs::read_dir(&self.state_directory) {
            Ok(entries) => entries
                .map(|entry| entry.expect("state entry should be readable").path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(".flowprobe-runtime-"))
                })
                .collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("state directory should be readable: {error}"),
        }
    }

    fn mark_crash(&self) {
        fs::write(self.root.join("crash-now"), b"crash").expect("crash marker should be written");
    }

    fn release_leader(&self) {
        fs::write(self.root.join("release-leader"), b"release")
            .expect("leader release marker should be written");
    }

    fn argv_log(&self) -> String {
        fs::read_to_string(self.root.join("argv.log")).expect("argv log should exist")
    }

    fn recorded_pid(&self, name: &str) -> i32 {
        fs::read_to_string(self.root.join(name))
            .expect("recorded process id should exist")
            .trim()
            .parse()
            .expect("recorded process id should be numeric")
    }

    fn wait_for_marker(&self, name: &str) {
        let marker = self.root.join(name);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !marker.is_file() {
            assert!(
                Instant::now() < deadline,
                "fake runtime did not write {name} in time"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.root)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("failed to remove isolated sing-box test directory: {error}");
        }
    }
}

fn compile_with(
    validator: impl RuntimeConfigValidator,
    system_json: &str,
    user_json: &str,
) -> Result<CompiledConfig, flowprobe_config_compiler::ConfigError> {
    ConfigCompiler::new(validator).compile(
        &SystemBase::parse(system_json).expect("system layer should parse"),
        &UserProfile::parse(user_json).expect("user layer should parse"),
        &RuntimeOverlay::parse("{}").expect("overlay layer should parse"),
    )
}

fn unchecked_config(user_json: &str) -> CompiledConfig {
    compile_with(AcceptConfig, "{}", user_json).expect("test config should compile")
}

fn assert_typed_unsupported<T: std::fmt::Debug>(
    result: Result<T, RuntimeError>,
    operation: RuntimeOperation,
    capability: RuntimeCapability,
) {
    assert_eq!(
        result.expect_err("operation should be unsupported"),
        RuntimeError::Unsupported {
            operation,
            capability,
        }
    );
}

fn assert_process_gone(process_id: i32) {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match kill(Pid::from_raw(process_id), None) {
            Err(Errno::ESRCH) => return,
            Ok(()) | Err(Errno::EPERM) => {
                assert!(
                    Instant::now() < deadline,
                    "process {process_id} was not cleaned up"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("process liveness check failed: {error}"),
        }
    }
}

fn assert_process_alive(process_id: i32) {
    match kill(Pid::from_raw(process_id), None) {
        Ok(()) | Err(Errno::EPERM) => {}
        Err(error) => panic!("process {process_id} should be alive: {error}"),
    }
}

fn assert_process_group_alive(process_group_id: i32) {
    match killpg(Pid::from_raw(process_group_id), None) {
        Ok(()) | Err(Errno::EPERM) => {}
        Err(error) => panic!("process group {process_group_id} should be alive: {error}"),
    }
}

fn assert_process_group_gone(process_group_id: i32) {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match killpg(Pid::from_raw(process_group_id), None) {
            Err(Errno::ESRCH) => return,
            Ok(()) | Err(Errno::EPERM) => {
                assert!(
                    Instant::now() < deadline,
                    "process group {process_group_id} was not cleaned up"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("process-group liveness check failed: {error}"),
        }
    }
}

fn assert_runtime_configs_gone(directory: &TestDirectory) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if directory.runtime_config_files().is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "private runtime configuration was not cleaned up"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn documented_cli_lifecycle_is_bounded_idempotent_and_private() {
    let directory = TestDirectory::new("normal");
    let runtime = SingBoxRuntime::new(directory.options()).expect("runtime should initialize");
    let secret = "not-a-real-runtime-password";
    let config = compile_with(
        &runtime,
        r#"{"outbounds":[{"tag":"__flowprobe_direct","type":"direct"}]}"#,
        &format!(r#"{{"credentials":{{"password":"{secret}"}}}}"#),
    )
    .expect("runtime should validate the config");

    runtime
        .validate_config(&config)
        .expect("explicit validation should succeed");
    assert_eq!(
        runtime.version().expect("version should succeed").as_str(),
        "sing-box version 1.12.0"
    );
    let capabilities = runtime
        .capabilities()
        .expect("capability query should succeed");
    assert!(capabilities.supports(RuntimeCapability::ConfigValidation));
    assert!(capabilities.supports(RuntimeCapability::ProcessLifecycle));
    assert!(capabilities.supports(RuntimeCapability::DirectEgress));
    assert!(!capabilities.supports(RuntimeCapability::ConfigReload));

    let started = runtime.start(&config).expect("runtime should start");
    assert_eq!(started.phase(), RuntimePhase::Running);
    assert!(matches!(
        started,
        RuntimeState::Running {
            generation: 1,
            process_id: Some(_),
        }
    ));
    let command_count = directory.argv_log().lines().count();
    assert_eq!(
        runtime
            .start(&config)
            .expect("same start should be idempotent"),
        started
    );
    assert_eq!(directory.argv_log().lines().count(), command_count);
    assert_eq!(
        runtime.start(&unchecked_config(r#"{"log":{"level":"warn"}}"#)),
        Err(RuntimeError::InvalidState {
            operation: RuntimeOperation::Start,
            actual: RuntimePhase::Running,
            required: RuntimePhase::Stopped,
        })
    );
    assert_eq!(
        runtime.health().expect("health should succeed"),
        RuntimeHealth::Healthy
    );
    let status = runtime.status().expect("status should succeed");
    assert_eq!(status.state, started);
    assert_eq!(status.health, RuntimeHealth::Healthy);
    assert_eq!(status.active_connections, None);
    assert_eq!(directory.runtime_config_files().len(), 1);
    let metadata = fs::metadata(&directory.runtime_config_files()[0])
        .expect("active config metadata should be readable");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(&directory.state_directory)
            .expect("state directory metadata should be readable")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(!format!("{runtime:?}").contains(secret));
    assert!(!format!("{runtime:?}").contains(directory.root.to_string_lossy().as_ref()));

    assert_typed_unsupported(
        runtime.apply_config(&config),
        RuntimeOperation::ApplyConfig,
        RuntimeCapability::ConfigReload,
    );
    assert_typed_unsupported(
        runtime.proxy_groups(),
        RuntimeOperation::ProxyGroups,
        RuntimeCapability::ProxyGroups,
    );
    assert_typed_unsupported(
        runtime.select_proxy(
            &ProxyGroupId::new("group").expect("group id should be valid"),
            &ProxyId::new("proxy").expect("proxy id should be valid"),
        ),
        RuntimeOperation::SelectProxy,
        RuntimeCapability::ProxyGroups,
    );
    assert_typed_unsupported(
        runtime.connections(),
        RuntimeOperation::Connections,
        RuntimeCapability::ConnectionListing,
    );
    assert_typed_unsupported(
        runtime.probe_direct_egress(),
        RuntimeOperation::ProbeDirectEgress,
        RuntimeCapability::DirectEgressProbe,
    );

    assert_eq!(
        runtime.stop().expect("stop should succeed"),
        RuntimeState::Stopped { generation: 1 }
    );
    assert!(directory.runtime_config_files().is_empty());
    assert_eq!(
        runtime.stop().expect("second stop should be idempotent"),
        RuntimeState::Stopped { generation: 1 }
    );

    let argv = directory.argv_log();
    assert!(argv.lines().any(|line| line == "version"));
    assert!(argv.lines().any(|line| line.ends_with(" check")));
    assert!(argv.lines().any(|line| line.ends_with(" run")));
    assert!(argv.contains(directory.state_directory.to_string_lossy().as_ref()));
}

#[test]
fn direct_egress_config_is_accepted_and_started_without_a_control_surface() {
    let directory = TestDirectory::new("require_direct");
    let runtime = SingBoxRuntime::new(directory.options()).expect("runtime should initialize");
    let config = compile_with(
        &runtime,
        r#"{"outbounds":[{"tag":"__flowprobe_direct","type":"direct"}]}"#,
        "{}",
    )
    .expect("fake schema checker should require and accept direct egress");

    assert!(
        runtime
            .capabilities()
            .expect("capabilities should succeed")
            .supports(RuntimeCapability::DirectEgress)
    );
    assert_eq!(
        runtime
            .start(&config)
            .expect("direct config should start")
            .phase(),
        RuntimePhase::Running
    );
    assert_typed_unsupported(
        runtime.probe_direct_egress(),
        RuntimeOperation::ProbeDirectEgress,
        RuntimeCapability::DirectEgressProbe,
    );
    runtime.stop().expect("runtime should stop");
}

#[test]
fn validator_rejection_is_typed_and_never_exposes_config_or_process_output() {
    let directory = TestDirectory::new("check_reject");
    let runtime = SingBoxRuntime::new(directory.options()).expect("runtime should initialize");
    let secret = "not-a-real-secret-echoed-by-runtime";
    let error = compile_with(&runtime, "{}", &format!(r#"{{"password":"{secret}"}}"#))
        .expect_err("runtime validation should reject the config");

    assert!(!format!("{error:?} {error}").contains(secret));
    assert!(
        error
            .report()
            .diagnostics()
            .iter()
            .all(|diagnostic| !format!("{diagnostic:?}").contains(secret))
    );

    let raw_config = unchecked_config(&format!(r#"{{"password":"{secret}"}}"#));
    let runtime_error = runtime
        .validate_config(&raw_config)
        .expect_err("direct validation should reject");
    assert_eq!(runtime_error, RuntimeError::ValidationRejected);
    assert!(!format!("{runtime_error:?} {runtime_error}").contains(secret));
    assert!(directory.runtime_config_files().is_empty());
}

#[test]
fn command_timeout_and_output_limit_are_typed_and_processes_are_cleaned_up() {
    let timeout_directory = TestDirectory::new("version_timeout");
    let mut timeout_options = timeout_directory.options();
    timeout_options.command_timeout = Duration::from_secs(1);
    timeout_options.stop_timeout = Duration::from_millis(50);
    let timeout_runtime =
        Arc::new(SingBoxRuntime::new(timeout_options).expect("timeout runtime should initialize"));
    let worker_runtime = Arc::clone(&timeout_runtime);
    let worker = thread::spawn(move || worker_runtime.version());
    timeout_directory.wait_for_marker("timeout-ready");
    let leader_pid = timeout_directory.recorded_pid("last-pid");
    let descendant_pid = timeout_directory.recorded_pid("descendant-pid");
    let cleanup = ProcessGroupCleanup::new(leader_pid);
    assert_process_alive(leader_pid);
    assert_process_alive(descendant_pid);
    assert_process_group_alive(leader_pid);
    assert_eq!(
        worker.join().expect("version worker should not panic"),
        Err(RuntimeError::TimedOut {
            operation: RuntimeOperation::Version,
            timeout_ms: 1_000,
        })
    );
    assert_process_gone(leader_pid);
    assert_process_gone(descendant_pid);
    assert_process_group_gone(leader_pid);
    cleanup.confirm_gone();

    let output_directory = TestDirectory::new("version_large");
    let mut output_options = output_directory.options();
    output_options.max_version_output_bytes = 32;
    let output_runtime =
        SingBoxRuntime::new(output_options).expect("output runtime should initialize");
    assert_eq!(
        output_runtime.version(),
        Err(RuntimeError::OutputLimitExceeded {
            operation: RuntimeOperation::Version,
            limit: 32,
        })
    );
}

#[test]
fn extremely_short_version_cleanup_is_handed_to_the_bounded_reaper() {
    let directory = TestDirectory::new("version_descendant_release");
    let mut options = directory.options();
    options.stop_timeout = Duration::from_nanos(1);
    let runtime = Arc::new(SingBoxRuntime::new(options).expect("runtime should initialize"));
    let worker_runtime = Arc::clone(&runtime);
    let worker = thread::spawn(move || worker_runtime.version());
    directory.wait_for_marker("group-cleanup-ready");
    let leader_pid = directory.recorded_pid("last-pid");
    let descendant_pid = directory.recorded_pid("descendant-pid");
    let cleanup = ProcessGroupCleanup::new(leader_pid);
    assert_process_alive(leader_pid);
    assert_process_alive(descendant_pid);
    assert_process_group_alive(leader_pid);
    directory.release_leader();

    assert_eq!(
        worker.join().expect("version worker should not panic"),
        Err(RuntimeError::TimedOut {
            operation: RuntimeOperation::Version,
            timeout_ms: 1,
        })
    );
    assert_process_gone(leader_pid);
    assert_process_gone(descendant_pid);
    assert_process_group_gone(leader_pid);
    cleanup.confirm_gone();
}

#[test]
fn extremely_short_check_cleanup_retains_config_until_reaped() {
    let directory = TestDirectory::new("check_descendant_release");
    let mut options = directory.options();
    options.stop_timeout = Duration::from_nanos(1);
    let runtime = Arc::new(SingBoxRuntime::new(options).expect("runtime should initialize"));
    let config = unchecked_config("{}");
    let worker_runtime = Arc::clone(&runtime);
    let worker = thread::spawn(move || worker_runtime.validate_config(&config));
    directory.wait_for_marker("group-cleanup-ready");
    let leader_pid = directory.recorded_pid("last-pid");
    let descendant_pid = directory.recorded_pid("descendant-pid");
    let cleanup = ProcessGroupCleanup::new(leader_pid);
    assert_process_alive(leader_pid);
    assert_process_alive(descendant_pid);
    assert_process_group_alive(leader_pid);
    assert_eq!(directory.runtime_config_files().len(), 1);
    directory.release_leader();

    assert_eq!(
        worker.join().expect("check worker should not panic"),
        Err(RuntimeError::TimedOut {
            operation: RuntimeOperation::ValidateConfig,
            timeout_ms: 1,
        })
    );
    assert_process_gone(leader_pid);
    assert_process_gone(descendant_pid);
    assert_process_group_gone(leader_pid);
    assert_runtime_configs_gone(&directory);
    cleanup.confirm_gone();
}

#[test]
fn extremely_short_startup_cleanup_hands_off_child_and_config_together() {
    let directory = TestDirectory::new("run_early_exit_release");
    let mut options = directory.options();
    options.stop_timeout = Duration::from_nanos(1);
    let runtime = Arc::new(SingBoxRuntime::new(options).expect("runtime should initialize"));
    let config = unchecked_config("{}");
    let worker_runtime = Arc::clone(&runtime);
    let worker = thread::spawn(move || worker_runtime.start(&config));
    directory.wait_for_marker("group-cleanup-ready");
    let leader_pid = directory.recorded_pid("last-pid");
    let descendant_pid = directory.recorded_pid("descendant-pid");
    let cleanup = ProcessGroupCleanup::new(leader_pid);
    assert_process_alive(leader_pid);
    assert_process_alive(descendant_pid);
    assert_process_group_alive(leader_pid);
    assert_eq!(directory.runtime_config_files().len(), 1);
    directory.release_leader();

    assert_eq!(
        worker.join().expect("startup worker should not panic"),
        Err(RuntimeError::TimedOut {
            operation: RuntimeOperation::Start,
            timeout_ms: 1,
        })
    );
    assert_process_gone(leader_pid);
    assert_process_gone(descendant_pid);
    assert_process_group_gone(leader_pid);
    assert_runtime_configs_gone(&directory);
    cleanup.confirm_gone();
}

#[test]
fn runtime_drop_hands_extremely_short_cleanup_to_its_single_reaper() {
    let directory = TestDirectory::new("run_leader_exits_descendant_ignores_term");
    let leader_pid;
    let descendant_pid;
    let cleanup;
    {
        let mut options = directory.options();
        options.stop_timeout = Duration::from_nanos(1);
        let runtime = SingBoxRuntime::new(options).expect("runtime should initialize");
        runtime
            .start(&unchecked_config("{}"))
            .expect("runtime should start");
        directory.wait_for_marker("group-cleanup-ready");
        leader_pid = directory.recorded_pid("last-pid");
        descendant_pid = directory.recorded_pid("descendant-pid");
        cleanup = ProcessGroupCleanup::new(leader_pid);
        assert_process_alive(leader_pid);
        assert_process_alive(descendant_pid);
        assert_process_group_alive(leader_pid);
        assert_eq!(directory.runtime_config_files().len(), 1);
    }

    assert_process_gone(leader_pid);
    assert_process_gone(descendant_pid);
    assert_process_group_gone(leader_pid);
    assert_runtime_configs_gone(&directory);
    cleanup.confirm_gone();
}

#[test]
fn version_exit_and_invalid_bytes_have_distinct_typed_failures() {
    let exit_directory = TestDirectory::new("version_exit");
    let exit_runtime =
        SingBoxRuntime::new(exit_directory.options()).expect("exit runtime should initialize");
    assert_eq!(
        exit_runtime.version(),
        Err(RuntimeError::ProcessExited {
            operation: RuntimeOperation::Version,
            exit_code: Some(19),
        })
    );

    let invalid_directory = TestDirectory::new("version_invalid_utf8");
    let invalid_runtime = SingBoxRuntime::new(invalid_directory.options())
        .expect("invalid-output runtime should initialize");
    assert_eq!(
        invalid_runtime.version(),
        Err(RuntimeError::InvalidOutput {
            operation: RuntimeOperation::Version,
        })
    );
}

#[test]
fn completed_version_commands_reclaim_their_original_process_groups() {
    for (behavior, expected) in [
        ("version_descendant_normal", Ok("sing-box version 1.12.0")),
        ("version_descendant_exit", Err(Some(19))),
    ] {
        let directory = TestDirectory::new(behavior);
        let runtime =
            SingBoxRuntime::new(directory.options()).expect("version runtime should initialize");

        let result = runtime.version();
        directory.wait_for_marker("group-cleanup-ready");
        let leader_pid = directory.recorded_pid("last-pid");
        let descendant_pid = directory.recorded_pid("descendant-pid");
        match expected {
            Ok(version) => assert_eq!(
                result
                    .expect("normal version command should succeed")
                    .as_str(),
                version
            ),
            Err(exit_code) => assert_eq!(
                result,
                Err(RuntimeError::ProcessExited {
                    operation: RuntimeOperation::Version,
                    exit_code,
                })
            ),
        }
        assert_process_gone(leader_pid);
        assert_process_gone(descendant_pid);
        assert_process_group_gone(leader_pid);
    }
}

#[test]
fn completed_check_commands_reclaim_their_original_process_groups() {
    for (behavior, expected) in [
        ("check_descendant_normal", Ok(())),
        (
            "check_descendant_exit",
            Err(RuntimeError::ValidationRejected),
        ),
    ] {
        let directory = TestDirectory::new(behavior);
        let runtime =
            SingBoxRuntime::new(directory.options()).expect("check runtime should initialize");

        assert_eq!(runtime.validate_config(&unchecked_config("{}")), expected);
        directory.wait_for_marker("group-cleanup-ready");
        let leader_pid = directory.recorded_pid("last-pid");
        let descendant_pid = directory.recorded_pid("descendant-pid");
        assert_process_gone(leader_pid);
        assert_process_gone(descendant_pid);
        assert_process_group_gone(leader_pid);
        assert!(directory.runtime_config_files().is_empty());
    }
}

#[test]
fn version_reclaims_a_descendant_that_holds_the_output_pipe_open() {
    let directory = TestDirectory::new("version_pipe_descendant");
    let runtime = SingBoxRuntime::new(directory.options()).expect("runtime should initialize");

    assert_eq!(
        runtime.version().expect("version should finish").as_str(),
        "sing-box version 1.12.0"
    );
    directory.wait_for_marker("group-cleanup-ready");
    let leader_pid = directory.recorded_pid("last-pid");
    let descendant_pid = directory.recorded_pid("descendant-pid");
    assert_process_gone(leader_pid);
    assert_process_gone(descendant_pid);
    assert_process_group_gone(leader_pid);
}

#[test]
fn immediate_exit_and_later_crash_are_observed_without_leaking_config_files() {
    let exit_directory = TestDirectory::new("run_exit");
    let exit_runtime =
        SingBoxRuntime::new(exit_directory.options()).expect("exit runtime should initialize");
    let config = unchecked_config("{}");
    assert_eq!(
        exit_runtime.start(&config),
        Err(RuntimeError::ProcessExited {
            operation: RuntimeOperation::Start,
            exit_code: Some(42),
        })
    );
    assert_eq!(
        exit_runtime.state().expect("state should remain available"),
        RuntimeState::Stopped { generation: 0 }
    );
    assert!(exit_directory.runtime_config_files().is_empty());

    let crash_directory = TestDirectory::new("run_crash_marker");
    let crash_runtime =
        SingBoxRuntime::new(crash_directory.options()).expect("crash runtime should initialize");
    crash_runtime.start(&config).expect("runtime should start");
    crash_directory.wait_for_marker("run-ready");
    crash_directory.mark_crash();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let state = crash_runtime.state().expect("state query should succeed");
        if state.phase() == RuntimePhase::Crashed {
            assert_eq!(
                state,
                RuntimeState::Crashed {
                    generation: 1,
                    exit_code: Some(42),
                }
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fake runtime did not crash in time"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        crash_runtime.health().expect("health should succeed"),
        RuntimeHealth::Unhealthy {
            exit_code: Some(42),
        }
    );
    assert!(crash_directory.runtime_config_files().is_empty());
}

#[test]
fn startup_early_exit_reclaims_a_ready_term_ignoring_descendant() {
    let directory = TestDirectory::new("run_early_exit_with_descendant");
    let runtime = SingBoxRuntime::new(directory.options()).expect("runtime should initialize");

    assert_eq!(
        runtime.start(&unchecked_config("{}")),
        Err(RuntimeError::ProcessExited {
            operation: RuntimeOperation::Start,
            exit_code: Some(42),
        })
    );
    directory.wait_for_marker("group-cleanup-ready");
    let leader_pid = directory.recorded_pid("last-pid");
    let descendant_pid = directory.recorded_pid("descendant-pid");
    assert_process_gone(leader_pid);
    assert_process_gone(descendant_pid);
    assert_process_group_gone(leader_pid);
    assert!(directory.runtime_config_files().is_empty());
}

#[test]
fn natural_crash_refresh_reclaims_descendants_before_reporting_the_crash() {
    for query in ["health", "state", "status"] {
        let directory = TestDirectory::new("run_crash_with_descendant");
        let runtime = SingBoxRuntime::new(directory.options()).expect("runtime should initialize");
        runtime
            .start(&unchecked_config("{}"))
            .expect("runtime should start");
        directory.wait_for_marker("group-cleanup-ready");
        let leader_pid = directory.recorded_pid("last-pid");
        let descendant_pid = directory.recorded_pid("descendant-pid");
        assert_process_alive(leader_pid);
        assert_process_alive(descendant_pid);
        assert_process_group_alive(leader_pid);
        directory.mark_crash();
        directory.wait_for_marker("leader-exiting");

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let crashed = match query {
                "health" => matches!(
                    runtime.health().expect("health query should succeed"),
                    RuntimeHealth::Unhealthy {
                        exit_code: Some(42)
                    }
                ),
                "state" => matches!(
                    runtime.state().expect("state query should succeed"),
                    RuntimeState::Crashed {
                        generation: 1,
                        exit_code: Some(42)
                    }
                ),
                "status" => {
                    let status = runtime.status().expect("status query should succeed");
                    matches!(
                        status.state,
                        RuntimeState::Crashed {
                            generation: 1,
                            exit_code: Some(42)
                        }
                    ) && matches!(
                        status.health,
                        RuntimeHealth::Unhealthy {
                            exit_code: Some(42)
                        }
                    )
                }
                _ => unreachable!("test query is fixed"),
            };
            if crashed {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "runtime did not report its crash"
            );
            thread::sleep(Duration::from_millis(10));
        }

        assert_process_gone(leader_pid);
        assert_process_gone(descendant_pid);
        assert_process_group_gone(leader_pid);
        assert!(directory.runtime_config_files().is_empty());
    }
}

#[test]
fn stop_after_natural_crash_reclaims_descendants_before_returning() {
    let directory = TestDirectory::new("run_crash_with_descendant");
    let runtime = SingBoxRuntime::new(directory.options()).expect("runtime should initialize");
    runtime
        .start(&unchecked_config("{}"))
        .expect("runtime should start");
    directory.wait_for_marker("group-cleanup-ready");
    let leader_pid = directory.recorded_pid("last-pid");
    let descendant_pid = directory.recorded_pid("descendant-pid");
    assert_process_alive(descendant_pid);
    assert_process_group_alive(leader_pid);
    directory.mark_crash();
    directory.wait_for_marker("leader-exiting");
    thread::sleep(Duration::from_millis(50));

    assert_eq!(
        runtime.stop().expect("stop should clean the crashed group"),
        RuntimeState::Stopped { generation: 1 }
    );
    assert_process_gone(leader_pid);
    assert_process_gone(descendant_pid);
    assert_process_group_gone(leader_pid);
    assert!(directory.runtime_config_files().is_empty());
}

#[test]
fn stop_escalates_to_kill_for_a_process_that_ignores_termination() {
    let directory = TestDirectory::new("run_ignore_term");
    let mut options = directory.options();
    options.stop_timeout = Duration::from_millis(50);
    let runtime = SingBoxRuntime::new(options).expect("runtime should initialize");
    runtime
        .start(&unchecked_config("{}"))
        .expect("stubborn runtime should start");
    directory.wait_for_marker("run-ignore-term-ready");
    let leader_pid = directory.recorded_pid("last-pid");
    assert_process_alive(leader_pid);
    assert_process_group_alive(leader_pid);

    let started = Instant::now();
    assert_eq!(
        runtime.stop().expect("stop should escalate and succeed"),
        RuntimeState::Stopped { generation: 1 }
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_process_gone(leader_pid);
    assert_process_group_gone(leader_pid);
    assert!(directory.runtime_config_files().is_empty());
}

#[test]
fn stop_kills_term_ignoring_descendant_after_leader_exits() {
    let directory = TestDirectory::new("run_leader_exits_descendant_ignores_term");
    let mut options = directory.options();
    options.stop_timeout = Duration::from_secs(2);
    let runtime = SingBoxRuntime::new(options).expect("runtime should initialize");
    runtime
        .start(&unchecked_config("{}"))
        .expect("runtime with a descendant should start");
    directory.wait_for_marker("group-cleanup-ready");
    let leader_pid = directory.recorded_pid("last-pid");
    let descendant_pid = directory.recorded_pid("descendant-pid");
    assert_process_alive(leader_pid);
    assert_process_alive(descendant_pid);
    assert_process_group_alive(leader_pid);

    let started = Instant::now();
    assert_eq!(
        runtime.stop().expect("process group stop should succeed"),
        RuntimeState::Stopped { generation: 1 }
    );
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "leader exit should trigger immediate residual-group cleanup"
    );
    assert_process_gone(leader_pid);
    assert_process_gone(descendant_pid);
    assert_process_group_gone(leader_pid);
    assert!(directory.runtime_config_files().is_empty());
}

#[test]
fn unsafe_or_unusable_paths_and_options_are_rejected_without_path_disclosure() {
    let directory = TestDirectory::new("normal");
    let mut relative = directory.options();
    relative.executable = PathBuf::from("sing-box");
    assert_eq!(
        SingBoxRuntime::new(relative).expect_err("relative executable must fail"),
        RuntimeError::InvalidInput {
            operation: RuntimeOperation::Initialize,
            field: "executable",
            reason: "path must be absolute",
        }
    );

    let mut missing = directory.options();
    missing.executable = directory.root.join("missing-secret-name");
    let error = SingBoxRuntime::new(missing).expect_err("missing executable must fail");
    assert_eq!(
        error,
        RuntimeError::Unavailable {
            operation: RuntimeOperation::Initialize,
            reason: RuntimeUnavailableReason::ExecutableMissing,
        }
    );
    assert!(!format!("{error:?} {error}").contains("missing-secret-name"));

    let target = directory.root.join("real-state");
    fs::create_dir(&target).expect("real state should be created");
    let link = directory.root.join("linked-state");
    symlink(&target, &link).expect("state symlink should be created");
    let mut linked = directory.options();
    linked.state_directory = link;
    assert_eq!(
        SingBoxRuntime::new(linked).expect_err("state symlink must fail"),
        RuntimeError::InvalidInput {
            operation: RuntimeOperation::Initialize,
            field: "state_directory",
            reason: "symbolic links are not accepted",
        }
    );

    let insecure = directory.root.join("insecure-state");
    fs::create_dir(&insecure).expect("insecure state should be created");
    fs::set_permissions(&insecure, fs::Permissions::from_mode(0o777))
        .expect("insecure state permissions should be set");
    let mut insecure_options = directory.options();
    insecure_options.state_directory = insecure;
    assert_eq!(
        SingBoxRuntime::new(insecure_options).expect_err("writable state dir must fail"),
        RuntimeError::InvalidInput {
            operation: RuntimeOperation::Initialize,
            field: "state_directory",
            reason: "directory is group or world writable",
        }
    );

    let mut invalid_timeout = directory.options();
    invalid_timeout.command_timeout = Duration::ZERO;
    assert!(matches!(
        SingBoxRuntime::new(invalid_timeout),
        Err(RuntimeError::InvalidInput {
            operation: RuntimeOperation::Initialize,
            field: "command_timeout",
            ..
        })
    ));

    let mut invalid_config_limit = directory.options();
    invalid_config_limit.max_config_bytes = 0;
    assert!(matches!(
        SingBoxRuntime::new(invalid_config_limit),
        Err(RuntimeError::InvalidInput {
            operation: RuntimeOperation::Initialize,
            field: "max_config_bytes",
            ..
        })
    ));
}

#[test]
fn compiled_config_size_limit_applies_before_writing_or_spawning() {
    let directory = TestDirectory::new("normal");
    let mut options = directory.options();
    options.max_config_bytes = 16;
    let runtime = SingBoxRuntime::new(options).expect("runtime should initialize");
    let config = unchecked_config(r#"{"value":"this config is intentionally too large"}"#);

    assert_eq!(
        runtime.validate_config(&config),
        Err(RuntimeError::InvalidInput {
            operation: RuntimeOperation::ValidateConfig,
            field: "compiled_config",
            reason: "configuration exceeds its byte limit",
        })
    );
    assert!(directory.runtime_config_files().is_empty());
    assert!(!directory.root.join("argv.log").exists());
}

#[test]
fn check_timeout_maps_to_validator_unavailable_without_committing_a_config() {
    let directory = TestDirectory::new("check_timeout");
    let mut options = directory.options();
    options.command_timeout = Duration::from_secs(1);
    options.stop_timeout = Duration::from_millis(50);
    let runtime = Arc::new(SingBoxRuntime::new(options).expect("runtime should initialize"));
    let worker_runtime = Arc::clone(&runtime);
    let worker = thread::spawn(move || {
        RuntimeConfigValidator::validate(
            worker_runtime.as_ref(),
            r#"{"password":"not-a-real-secret"}"#,
        )
    });
    directory.wait_for_marker("timeout-ready");
    let leader_pid = directory.recorded_pid("last-pid");
    let descendant_pid = directory.recorded_pid("descendant-pid");
    let cleanup = ProcessGroupCleanup::new(leader_pid);
    assert_process_alive(leader_pid);
    assert_process_alive(descendant_pid);
    assert_process_group_alive(leader_pid);
    assert_eq!(
        worker.join().expect("check worker should not panic"),
        Err(RuntimeValidationFailure::Unavailable)
    );
    assert_process_gone(leader_pid);
    assert_process_gone(descendant_pid);
    assert_process_group_gone(leader_pid);
    cleanup.confirm_gone();
    assert_runtime_configs_gone(&directory);
}

#[test]
fn abnormal_check_exit_is_not_misreported_as_invalid_configuration() {
    let directory = TestDirectory::new("check_signal");
    let runtime = SingBoxRuntime::new(directory.options()).expect("runtime should initialize");
    let config = unchecked_config("{}");

    assert_eq!(
        runtime.validate_config(&config),
        Err(RuntimeError::ProcessExited {
            operation: RuntimeOperation::ValidateConfig,
            exit_code: None,
        })
    );
    assert!(directory.runtime_config_files().is_empty());
}

#[test]
fn run_spawn_failure_cleans_the_already_checked_private_config() {
    let directory = TestDirectory::new("remove_before_run");
    let runtime = SingBoxRuntime::new(directory.options()).expect("runtime should initialize");

    assert_eq!(
        runtime.start(&unchecked_config("{}")),
        Err(RuntimeError::Unavailable {
            operation: RuntimeOperation::Start,
            reason: RuntimeUnavailableReason::ExecutableMissing,
        })
    );
    assert!(directory.runtime_config_files().is_empty());
    assert_eq!(
        runtime.state().expect("state should remain queryable"),
        RuntimeState::Stopped { generation: 0 }
    );
}

#[test]
fn drop_stops_the_managed_process_and_removes_its_private_config() {
    let directory = TestDirectory::new("normal");
    let process_id;
    {
        let runtime = SingBoxRuntime::new(directory.options()).expect("runtime should initialize");
        runtime
            .start(&unchecked_config("{}"))
            .expect("runtime should start");
        assert_eq!(directory.runtime_config_files().len(), 1);
        process_id = directory.recorded_pid("last-pid");
    }
    assert_process_gone(process_id);
    assert!(directory.runtime_config_files().is_empty());
}

#[test]
fn drop_kills_term_ignoring_descendant_after_leader_exits() {
    let directory = TestDirectory::new("run_leader_exits_descendant_ignores_term");
    let leader_pid;
    let descendant_pid;
    {
        let runtime = SingBoxRuntime::new(directory.options()).expect("runtime should initialize");
        runtime
            .start(&unchecked_config("{}"))
            .expect("runtime with a descendant should start");
        directory.wait_for_marker("group-cleanup-ready");
        leader_pid = directory.recorded_pid("last-pid");
        descendant_pid = directory.recorded_pid("descendant-pid");
        assert_process_alive(leader_pid);
        assert_process_alive(descendant_pid);
        assert_process_group_alive(leader_pid);
    }

    assert_process_gone(leader_pid);
    assert_process_gone(descendant_pid);
    assert_process_group_gone(leader_pid);
    assert!(directory.runtime_config_files().is_empty());
}

#[test]
fn concurrent_same_config_start_is_linearizable_and_spawns_once() {
    use std::sync::{Arc, Barrier};

    let directory = TestDirectory::new("normal");
    let runtime =
        Arc::new(SingBoxRuntime::new(directory.options()).expect("runtime should initialize"));
    let config = Arc::new(unchecked_config("{}"));
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let runtime = Arc::clone(&runtime);
        let config = Arc::clone(&config);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            runtime.start(&config)
        }));
    }
    barrier.wait();
    let states = workers
        .into_iter()
        .map(|worker| worker.join().expect("start worker should not panic"))
        .collect::<Result<Vec<_>, _>>()
        .expect("both idempotent starts should succeed");

    assert_eq!(states[0], states[1]);
    directory.wait_for_marker("run-ready");
    assert_eq!(
        directory
            .argv_log()
            .lines()
            .filter(|line| line.ends_with(" run"))
            .count(),
        1
    );
    runtime.stop().expect("runtime should stop");
}

#[test]
fn config_cleanup_failure_is_typed_and_can_be_retried() {
    let directory = TestDirectory::new("normal");
    let runtime = SingBoxRuntime::new(directory.options()).expect("runtime should initialize");
    runtime
        .start(&unchecked_config("{}"))
        .expect("runtime should start");
    let config_path = directory.runtime_config_files().remove(0);
    fs::remove_file(&config_path).expect("private config should be removable by the test");
    fs::create_dir(&config_path).expect("replacement directory should be created");

    assert!(matches!(
        runtime.stop(),
        Err(RuntimeError::ProcessIo {
            operation: RuntimeOperation::Stop,
            ..
        })
    ));
    fs::remove_dir(&config_path).expect("replacement directory should be removed");
    assert_eq!(
        runtime.stop().expect("cleanup retry should succeed"),
        RuntimeState::Stopped { generation: 1 }
    );
}
