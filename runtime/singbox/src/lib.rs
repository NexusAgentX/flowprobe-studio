//! Thin managed-process adapter for the documented sing-box CLI.

use std::{
    collections::VecDeque,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Arc, Condvar, Mutex, MutexGuard, mpsc},
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::{fs::OpenOptionsExt, process::CommandExt};

use flowprobe_config_compiler::{RuntimeConfigValidator, RuntimeValidationFailure};
use flowprobe_runtime_api::{
    ApplyOutcome, CompiledConfig, DirectEgressStatus, NetworkRuntime, ProcessIoKind, ProxyGroup,
    ProxyGroupId, ProxyId, RuntimeCapabilities, RuntimeCapability, RuntimeConnection, RuntimeError,
    RuntimeHealth, RuntimeOperation, RuntimePhase, RuntimeResult, RuntimeState, RuntimeStatus,
    RuntimeVersion,
};

#[cfg(unix)]
use nix::{
    errno::Errno,
    sys::signal::{Signal, killpg},
    unistd::Pid,
};

const CLEANUP_REAPER_CAPACITY: usize = 64;
const MAX_CONFIG_CREATE_ATTEMPTS: usize = CLEANUP_REAPER_CAPACITY;
const MAX_ALLOWED_CONFIG_BYTES: usize = 8 * 1024 * 1024;
const MAX_ALLOWED_VERSION_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_ALLOWED_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ALLOWED_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const POST_SIGKILL_REAP_TIMEOUT: Duration = Duration::from_millis(250);
const CLEANUP_REAPER_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(250);

/// Process paths and bounded timing used by the managed adapter.
#[derive(Clone)]
pub struct SingBoxOptions {
    pub executable: PathBuf,
    pub state_directory: PathBuf,
    pub command_timeout: Duration,
    pub startup_probe_duration: Duration,
    pub stop_timeout: Duration,
    pub max_config_bytes: usize,
    pub max_version_output_bytes: usize,
}

impl fmt::Debug for SingBoxOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SingBoxOptions")
            .field("executable", &"<configured>")
            .field("state_directory", &"<configured>")
            .field("command_timeout", &self.command_timeout)
            .field("startup_probe_duration", &self.startup_probe_duration)
            .field("stop_timeout", &self.stop_timeout)
            .field("max_config_bytes", &self.max_config_bytes)
            .field("max_version_output_bytes", &self.max_version_output_bytes)
            .finish()
    }
}

/// Independent sing-box process implementing the NetworkRuntime boundary.
pub struct SingBoxRuntime {
    executable: PathBuf,
    state_directory: PathBuf,
    command_timeout: Duration,
    startup_probe_duration: Duration,
    stop_timeout: Duration,
    max_config_bytes: usize,
    max_version_output_bytes: usize,
    state: Mutex<ManagedState>,
    cleanup_reaper: CleanupReaper,
}

struct ManagedState {
    runtime_state: RuntimeState,
    child: Option<ManagedChild>,
    active_config: Option<ManagedConfig>,
    cleanup_permit: Option<CleanupPermit>,
}

struct ManagedChild {
    child: Child,
    #[cfg(unix)]
    process_group: Pid,
}

impl ManagedChild {
    fn new(child: Child, operation: RuntimeOperation) -> RuntimeResult<Self> {
        #[cfg(unix)]
        let process_group = match i32::try_from(child.id()) {
            Ok(process_group) => Pid::from_raw(process_group),
            Err(_) => {
                let mut child = child;
                let _kill_result = child.kill();
                let _wait_result = child.wait();
                return Err(RuntimeError::InternalState { operation });
            }
        };
        #[cfg(not(unix))]
        let _ = operation;

        Ok(Self {
            child,
            #[cfg(unix)]
            process_group,
        })
    }
}

struct ManagedConfig {
    path: PathBuf,
    runtime_json: String,
}

struct ConfigWriteFailure {
    error: RuntimeError,
    config: Option<ManagedConfig>,
}

impl ManagedConfig {
    fn cleanup(&mut self, operation: RuntimeOperation) -> RuntimeResult<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        match fs::remove_file(&self.path) {
            Ok(()) => {
                self.path.clear();
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.path.clear();
                Ok(())
            }
            Err(error) => Err(process_io(operation, &error)),
        }
    }
}

impl Drop for ManagedConfig {
    fn drop(&mut self) {
        // Defense in depth only: every intentional error path explicitly cleans
        // or transfers the config together with its reserved cleanup permit.
        if !self.path.as_os_str().is_empty() {
            let _remove_result = fs::remove_file(&self.path);
        }
    }
}

struct PendingCleanup {
    child: Option<ManagedChild>,
    config: Option<ManagedConfig>,
    permit: Option<CleanupPermit>,
    operation: RuntimeOperation,
}

impl PendingCleanup {
    fn new(
        child: Option<ManagedChild>,
        config: Option<ManagedConfig>,
        permit: Option<CleanupPermit>,
        operation: RuntimeOperation,
    ) -> Self {
        Self {
            child,
            config,
            permit,
            operation,
        }
    }

    fn is_empty(&self) -> bool {
        self.child.is_none() && self.config.is_none()
    }

    fn cleanup_once(&mut self, timeout: Duration) -> bool {
        if let Some(child) = self.child.as_mut() {
            if terminate_managed_child(child, self.operation, timeout).is_err() {
                return false;
            }
            self.child = None;
        }
        if let Some(config) = self.config.as_mut() {
            if config.cleanup(self.operation).is_err() {
                return false;
            }
            self.config = None;
        }
        self.permit = None;
        true
    }
}

struct CleanupQueueState {
    pending: VecDeque<PendingCleanup>,
    owned: usize,
    shutdown: bool,
    worker_running: bool,
}

struct CleanupQueue {
    state: Mutex<CleanupQueueState>,
    changed: Condvar,
}

struct CleanupReaper {
    queue: Arc<CleanupQueue>,
}

struct CleanupPermit {
    queue: Arc<CleanupQueue>,
}

impl Drop for CleanupPermit {
    fn drop(&mut self) {
        let mut state = lock_cleanup_queue(&self.queue);
        if state.owned > 0 {
            state.owned -= 1;
        }
        self.queue.changed.notify_all();
    }
}

impl CleanupReaper {
    fn new() -> RuntimeResult<Self> {
        let queue = Arc::new(CleanupQueue {
            state: Mutex::new(CleanupQueueState {
                pending: VecDeque::new(),
                owned: 0,
                shutdown: false,
                worker_running: true,
            }),
            changed: Condvar::new(),
        });
        let worker_queue = Arc::clone(&queue);
        thread::Builder::new()
            .name("flowprobe-runtime-reaper".to_owned())
            .spawn(move || cleanup_reaper_worker(worker_queue))
            .map_err(|error| process_io(RuntimeOperation::Initialize, &error))?;
        Ok(Self { queue })
    }

    fn acquire(&self, operation: RuntimeOperation) -> RuntimeResult<CleanupPermit> {
        let mut state = lock_cleanup_queue(&self.queue);
        if state.shutdown || state.owned >= CLEANUP_REAPER_CAPACITY {
            return Err(RuntimeError::Unavailable {
                operation,
                reason: flowprobe_runtime_api::RuntimeUnavailableReason::Other,
            });
        }
        state.owned += 1;
        Ok(CleanupPermit {
            queue: Arc::clone(&self.queue),
        })
    }

    fn handoff(&self, pending: PendingCleanup) {
        if pending.is_empty() {
            return;
        }
        let mut state = lock_cleanup_queue(&self.queue);
        state.pending.push_back(pending);
        self.queue.changed.notify_all();
    }
}

impl Drop for CleanupReaper {
    fn drop(&mut self) {
        let mut state = lock_cleanup_queue(&self.queue);
        state.shutdown = true;
        self.queue.changed.notify_all();
    }
}

struct ChildGuard<'a> {
    child: Option<ManagedChild>,
    config: Option<ManagedConfig>,
    permit: Option<CleanupPermit>,
    operation: RuntimeOperation,
    stop_timeout: Duration,
    cleanup_reaper: &'a CleanupReaper,
}

impl<'a> ChildGuard<'a> {
    fn new(
        child: Child,
        config: Option<ManagedConfig>,
        permit: CleanupPermit,
        operation: RuntimeOperation,
        stop_timeout: Duration,
        cleanup_reaper: &'a CleanupReaper,
    ) -> RuntimeResult<Self> {
        let child = match ManagedChild::new(child, operation) {
            Ok(child) => child,
            Err(error) => {
                if let Some(config) = config {
                    cleanup_config_or_handoff(config, permit, operation, cleanup_reaper);
                }
                return Err(error);
            }
        };
        Ok(Self {
            child: Some(child),
            config,
            permit: Some(permit),
            operation,
            stop_timeout,
            cleanup_reaper,
        })
    }

    fn child_mut(&mut self) -> RuntimeResult<&mut Child> {
        self.child
            .as_mut()
            .map(|managed| &mut managed.child)
            .ok_or(RuntimeError::InternalState {
                operation: self.operation,
            })
    }

    fn into_running_parts(mut self) -> RuntimeResult<(ManagedChild, ManagedConfig, CleanupPermit)> {
        if self.child.is_none() || self.config.is_none() || self.permit.is_none() {
            return Err(RuntimeError::InternalState {
                operation: self.operation,
            });
        }
        let child = self.child.take().ok_or(RuntimeError::InternalState {
            operation: self.operation,
        })?;
        let config = self.config.take().ok_or(RuntimeError::InternalState {
            operation: self.operation,
        })?;
        let permit = self.permit.take().ok_or(RuntimeError::InternalState {
            operation: self.operation,
        })?;
        Ok((child, config, permit))
    }

    fn terminate(&mut self) -> RuntimeResult<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if let Err(error) = terminate_managed_child(&mut child, self.operation, self.stop_timeout) {
            self.cleanup_reaper.handoff(PendingCleanup::new(
                Some(child),
                self.config.take(),
                self.permit.take(),
                self.operation,
            ));
            return Err(error);
        }
        if self.config.is_none() {
            self.permit = None;
        }
        Ok(())
    }

    fn cleanup_config(&mut self) -> RuntimeResult<()> {
        let Some(config) = self.config.as_mut() else {
            return Ok(());
        };
        config.cleanup(self.operation)?;
        self.config = None;
        if self.child.is_none() {
            self.permit = None;
        }
        Ok(())
    }

    fn handoff_remaining(&mut self) {
        self.cleanup_reaper.handoff(PendingCleanup::new(
            self.child.take(),
            self.config.take(),
            self.permit.take(),
            self.operation,
        ));
    }
}

impl Drop for ChildGuard<'_> {
    fn drop(&mut self) {
        self.handoff_remaining();
    }
}

fn cleanup_config_or_handoff(
    mut config: ManagedConfig,
    permit: CleanupPermit,
    operation: RuntimeOperation,
    cleanup_reaper: &CleanupReaper,
) {
    if config.cleanup(operation).is_err() {
        cleanup_reaper.handoff(PendingCleanup::new(
            None,
            Some(config),
            Some(permit),
            operation,
        ));
    }
}

fn spawn_configured_child<'a>(
    command: &mut Command,
    config: ManagedConfig,
    cleanup_permit: CleanupPermit,
    operation: RuntimeOperation,
    stop_timeout: Duration,
    cleanup_reaper: &'a CleanupReaper,
) -> RuntimeResult<ChildGuard<'a>> {
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let spawn_error = unavailable_for_io(operation, &error);
            cleanup_config_or_handoff(config, cleanup_permit, operation, cleanup_reaper);
            return Err(spawn_error);
        }
    };
    ChildGuard::new(
        child,
        Some(config),
        cleanup_permit,
        operation,
        stop_timeout,
        cleanup_reaper,
    )
}

fn lock_cleanup_queue(queue: &CleanupQueue) -> MutexGuard<'_, CleanupQueueState> {
    match queue.state.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn wait_cleanup_queue<'a>(
    queue: &'a CleanupQueue,
    state: MutexGuard<'a, CleanupQueueState>,
) -> MutexGuard<'a, CleanupQueueState> {
    match queue.changed.wait(state) {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn cleanup_reaper_worker(queue: Arc<CleanupQueue>) {
    loop {
        let mut pending = {
            let mut state = lock_cleanup_queue(&queue);
            while state.pending.is_empty() {
                if state.shutdown && state.owned == 0 {
                    state.worker_running = false;
                    queue.changed.notify_all();
                    return;
                }
                state = wait_cleanup_queue(&queue, state);
            }
            let Some(pending) = state.pending.pop_front() else {
                continue;
            };
            pending
        };

        let complete = pending.cleanup_once(CLEANUP_REAPER_ATTEMPT_TIMEOUT);
        let mut state = lock_cleanup_queue(&queue);
        if !complete {
            state.pending.push_back(pending);
        }
        queue.changed.notify_all();
        drop(state);
        if !complete {
            thread::sleep(POLL_INTERVAL);
        }
    }
}

impl fmt::Debug for SingBoxRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = self
            .state
            .lock()
            .map(|state| state.runtime_state.phase())
            .ok();
        formatter
            .debug_struct("SingBoxRuntime")
            .field("executable", &"<configured>")
            .field("state_directory", &"<configured>")
            .field("phase", &phase)
            .finish_non_exhaustive()
    }
}

impl SingBoxRuntime {
    pub fn new(options: SingBoxOptions) -> RuntimeResult<Self> {
        validate_options(&options)?;
        let executable = fs::canonicalize(&options.executable)
            .map_err(|error| unavailable_for_io(RuntimeOperation::Initialize, &error))?;
        if !executable.is_file() {
            return Err(RuntimeError::InvalidInput {
                operation: RuntimeOperation::Initialize,
                field: "executable",
                reason: "path is not a file",
            });
        }
        ensure_state_directory(&options.state_directory)?;
        let state_directory = fs::canonicalize(&options.state_directory)
            .map_err(|error| process_io(RuntimeOperation::Initialize, &error))?;
        if !state_directory.is_dir() {
            return Err(RuntimeError::InvalidInput {
                operation: RuntimeOperation::Initialize,
                field: "state_directory",
                reason: "path is not a directory",
            });
        }
        let cleanup_reaper = CleanupReaper::new()?;

        Ok(Self {
            executable,
            state_directory,
            command_timeout: options.command_timeout,
            startup_probe_duration: options.startup_probe_duration,
            stop_timeout: options.stop_timeout,
            max_config_bytes: options.max_config_bytes,
            max_version_output_bytes: options.max_version_output_bytes,
            state: Mutex::new(ManagedState {
                runtime_state: RuntimeState::Stopped { generation: 0 },
                child: None,
                active_config: None,
                cleanup_permit: None,
            }),
            cleanup_reaper,
        })
    }

    fn lock(&self, operation: RuntimeOperation) -> RuntimeResult<MutexGuard<'_, ManagedState>> {
        self.state
            .lock()
            .map_err(|_| RuntimeError::InternalState { operation })
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command.current_dir(&self.state_directory);
        command.stdin(Stdio::null());
        #[cfg(unix)]
        command.process_group(0);
        command
    }

    fn configured_command(&self, config_path: &Path, subcommand: &str) -> Command {
        let mut command = self.command();
        command
            .arg("-D")
            .arg(&self.state_directory)
            .arg("-c")
            .arg(config_path)
            .arg(subcommand);
        command
    }

    fn write_config(
        &self,
        runtime_json: &str,
        operation: RuntimeOperation,
    ) -> Result<ManagedConfig, ConfigWriteFailure> {
        if runtime_json.len() > self.max_config_bytes {
            return Err(ConfigWriteFailure {
                error: RuntimeError::InvalidInput {
                    operation,
                    field: "compiled_config",
                    reason: "configuration exceeds its byte limit",
                },
                config: None,
            });
        }
        for attempt in 0..MAX_CONFIG_CREATE_ATTEMPTS {
            let path = self.state_directory.join(format!(
                ".flowprobe-runtime-{}-{attempt}.json",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            match options.open(&path) {
                Ok(mut file) => {
                    let config = ManagedConfig {
                        path,
                        runtime_json: runtime_json.to_owned(),
                    };
                    if let Err(error) = write_private_config(&mut file, runtime_json) {
                        drop(file);
                        return Err(ConfigWriteFailure {
                            error: process_io(operation, &error),
                            config: Some(config),
                        });
                    }
                    return Ok(config);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(ConfigWriteFailure {
                        error: process_io(operation, &error),
                        config: None,
                    });
                }
            }
        }
        Err(ConfigWriteFailure {
            error: RuntimeError::ProcessIo {
                operation,
                kind: ProcessIoKind::AlreadyExists,
            },
            config: None,
        })
    }

    fn prepare_config(
        &self,
        runtime_json: &str,
        operation: RuntimeOperation,
    ) -> RuntimeResult<(ManagedConfig, CleanupPermit)> {
        let permit = self.cleanup_reaper.acquire(operation)?;
        match self.write_config(runtime_json, operation) {
            Ok(config) => Ok((config, permit)),
            Err(ConfigWriteFailure {
                error,
                config: Some(config),
            }) => {
                cleanup_config_or_handoff(config, permit, operation, &self.cleanup_reaper);
                Err(error)
            }
            Err(ConfigWriteFailure {
                error,
                config: None,
            }) => Err(error),
        }
    }

    fn check_runtime_json(&self, runtime_json: &str) -> RuntimeResult<()> {
        let (config, cleanup_permit) =
            self.prepare_config(runtime_json, RuntimeOperation::ValidateConfig)?;
        let mut command = self.configured_command(&config.path, "check");
        command.stdout(Stdio::null()).stderr(Stdio::null());
        run_status_command(
            &mut command,
            config,
            cleanup_permit,
            RuntimeOperation::ValidateConfig,
            self.command_timeout,
            self.stop_timeout,
            &self.cleanup_reaper,
        )
        .and_then(|status| {
            if status.success() {
                Ok(())
            } else if status.code().is_none() {
                Err(RuntimeError::ProcessExited {
                    operation: RuntimeOperation::ValidateConfig,
                    exit_code: None,
                })
            } else {
                Err(RuntimeError::ValidationRejected)
            }
        })
    }

    fn refresh_locked(
        &self,
        state: &mut ManagedState,
        operation: RuntimeOperation,
    ) -> RuntimeResult<()> {
        let Some(child) = state.child.as_mut() else {
            if state.runtime_state.phase() != RuntimePhase::Running {
                cleanup_active_config(state, operation)?;
            }
            return Ok(());
        };
        match child.child.try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => {
                terminate_managed_child(child, operation, self.stop_timeout)?;
                let generation = state.runtime_state.generation();
                state.child = None;
                state.runtime_state = RuntimeState::Crashed {
                    generation,
                    exit_code: status.code(),
                };
                cleanup_active_config(state, operation)?;
                Ok(())
            }
            Err(error) => Err(process_io(operation, &error)),
        }
    }

    fn capabilities_value() -> RuntimeCapabilities {
        RuntimeCapabilities::new([
            RuntimeCapability::ConfigValidation,
            RuntimeCapability::ProcessLifecycle,
            RuntimeCapability::Health,
            RuntimeCapability::Version,
            RuntimeCapability::DirectEgress,
            RuntimeCapability::RuntimeStatus,
        ])
    }

    fn unsupported<T>(
        operation: RuntimeOperation,
        capability: RuntimeCapability,
    ) -> RuntimeResult<T> {
        Err(RuntimeError::Unsupported {
            operation,
            capability,
        })
    }
}

impl RuntimeConfigValidator for SingBoxRuntime {
    fn validate(&self, canonical_runtime_json: &str) -> Result<(), RuntimeValidationFailure> {
        match self.check_runtime_json(canonical_runtime_json) {
            Ok(()) => Ok(()),
            Err(RuntimeError::ValidationRejected) => Err(RuntimeValidationFailure::Rejected),
            Err(_) => Err(RuntimeValidationFailure::Unavailable),
        }
    }
}

impl RuntimeConfigValidator for &SingBoxRuntime {
    fn validate(&self, canonical_runtime_json: &str) -> Result<(), RuntimeValidationFailure> {
        <SingBoxRuntime as RuntimeConfigValidator>::validate(*self, canonical_runtime_json)
    }
}

impl NetworkRuntime for SingBoxRuntime {
    fn validate_config(&self, config: &CompiledConfig) -> RuntimeResult<()> {
        self.check_runtime_json(config.runtime_json())
    }

    fn start(&self, config: &CompiledConfig) -> RuntimeResult<RuntimeState> {
        let mut state = self.lock(RuntimeOperation::Start)?;
        self.refresh_locked(&mut state, RuntimeOperation::Start)?;
        if state.runtime_state.phase() == RuntimePhase::Running {
            if state
                .active_config
                .as_ref()
                .is_some_and(|active| active.runtime_json == config.runtime_json())
            {
                return Ok(state.runtime_state.clone());
            }
            return Err(RuntimeError::InvalidState {
                operation: RuntimeOperation::Start,
                actual: RuntimePhase::Running,
                required: RuntimePhase::Stopped,
            });
        }
        let generation =
            state
                .runtime_state
                .generation()
                .checked_add(1)
                .ok_or(RuntimeError::InternalState {
                    operation: RuntimeOperation::Start,
                })?;

        self.check_runtime_json(config.runtime_json())?;
        let (managed_config, cleanup_permit) =
            self.prepare_config(config.runtime_json(), RuntimeOperation::Start)?;
        let mut command = self.configured_command(&managed_config.path, "run");
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let mut child = spawn_configured_child(
            &mut command,
            managed_config,
            cleanup_permit,
            RuntimeOperation::Start,
            self.stop_timeout,
            &self.cleanup_reaper,
        )?;
        let startup_result = wait_until(
            child.child_mut()?,
            self.startup_probe_duration,
            RuntimeOperation::Start,
        );
        let startup_status = match startup_result {
            Ok(status) => status,
            Err(error) => {
                child.terminate()?;
                child.cleanup_config()?;
                return Err(error);
            }
        };
        if let Some(status) = startup_status {
            child.terminate()?;
            child.cleanup_config()?;
            return Err(RuntimeError::ProcessExited {
                operation: RuntimeOperation::Start,
                exit_code: status.code(),
            });
        }

        let process_id = child.child_mut()?.id();
        let (managed_child, managed_config, cleanup_permit) = child.into_running_parts()?;
        state.child = Some(managed_child);
        state.active_config = Some(managed_config);
        state.cleanup_permit = Some(cleanup_permit);
        state.runtime_state = RuntimeState::Running {
            generation,
            process_id: Some(process_id),
        };
        Ok(state.runtime_state.clone())
    }

    fn stop(&self) -> RuntimeResult<RuntimeState> {
        let mut state = self.lock(RuntimeOperation::Stop)?;
        self.refresh_locked(&mut state, RuntimeOperation::Stop)?;
        let generation = state.runtime_state.generation();
        let Some(mut child) = state.child.take() else {
            state.runtime_state = RuntimeState::Stopped { generation };
            cleanup_active_config(&mut state, RuntimeOperation::Stop)?;
            return Ok(state.runtime_state.clone());
        };
        if let Err(error) =
            terminate_managed_child(&mut child, RuntimeOperation::Stop, self.stop_timeout)
        {
            state.child = Some(child);
            return Err(error);
        }
        state.runtime_state = RuntimeState::Stopped { generation };
        cleanup_active_config(&mut state, RuntimeOperation::Stop)?;
        Ok(state.runtime_state.clone())
    }

    fn health(&self) -> RuntimeResult<RuntimeHealth> {
        let mut state = self.lock(RuntimeOperation::Health)?;
        self.refresh_locked(&mut state, RuntimeOperation::Health)?;
        Ok(health_for_state(&state.runtime_state))
    }

    fn state(&self) -> RuntimeResult<RuntimeState> {
        let mut state = self.lock(RuntimeOperation::State)?;
        self.refresh_locked(&mut state, RuntimeOperation::State)?;
        Ok(state.runtime_state.clone())
    }

    fn apply_config(&self, _config: &CompiledConfig) -> RuntimeResult<ApplyOutcome> {
        Self::unsupported(
            RuntimeOperation::ApplyConfig,
            RuntimeCapability::ConfigReload,
        )
    }

    fn version(&self) -> RuntimeResult<RuntimeVersion> {
        let mut command = self.command();
        command
            .arg("version")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let bytes = run_bounded_output_command(
            &mut command,
            RuntimeOperation::Version,
            self.command_timeout,
            self.stop_timeout,
            self.max_version_output_bytes,
            &self.cleanup_reaper,
        )?;
        let text = std::str::from_utf8(&bytes).map_err(|_| RuntimeError::InvalidOutput {
            operation: RuntimeOperation::Version,
        })?;
        let first_line = text
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .ok_or(RuntimeError::InvalidOutput {
                operation: RuntimeOperation::Version,
            })?;
        RuntimeVersion::new(first_line).map_err(|_| RuntimeError::InvalidOutput {
            operation: RuntimeOperation::Version,
        })
    }

    fn capabilities(&self) -> RuntimeResult<RuntimeCapabilities> {
        Ok(Self::capabilities_value())
    }

    fn proxy_groups(&self) -> RuntimeResult<Vec<ProxyGroup>> {
        Self::unsupported(
            RuntimeOperation::ProxyGroups,
            RuntimeCapability::ProxyGroups,
        )
    }

    fn select_proxy(&self, _group: &ProxyGroupId, _proxy: &ProxyId) -> RuntimeResult<ProxyGroup> {
        Self::unsupported(
            RuntimeOperation::SelectProxy,
            RuntimeCapability::ProxyGroups,
        )
    }

    fn connections(&self) -> RuntimeResult<Vec<RuntimeConnection>> {
        Self::unsupported(
            RuntimeOperation::Connections,
            RuntimeCapability::ConnectionListing,
        )
    }

    fn status(&self) -> RuntimeResult<RuntimeStatus> {
        let mut state = self.lock(RuntimeOperation::Status)?;
        self.refresh_locked(&mut state, RuntimeOperation::Status)?;
        Ok(RuntimeStatus {
            state: state.runtime_state.clone(),
            health: health_for_state(&state.runtime_state),
            active_connections: None,
            uploaded_bytes: None,
            downloaded_bytes: None,
        })
    }

    fn probe_direct_egress(&self) -> RuntimeResult<DirectEgressStatus> {
        Self::unsupported(
            RuntimeOperation::ProbeDirectEgress,
            RuntimeCapability::DirectEgressProbe,
        )
    }
}

impl Drop for SingBoxRuntime {
    fn drop(&mut self) {
        let state = match self.state.get_mut() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut pending = PendingCleanup::new(
            state.child.take(),
            state.active_config.take(),
            state.cleanup_permit.take(),
            RuntimeOperation::Stop,
        );
        if !pending.cleanup_once(self.stop_timeout) {
            self.cleanup_reaper.handoff(pending);
        }
    }
}

fn validate_options(options: &SingBoxOptions) -> RuntimeResult<()> {
    if !options.executable.is_absolute() {
        return Err(RuntimeError::InvalidInput {
            operation: RuntimeOperation::Initialize,
            field: "executable",
            reason: "path must be absolute",
        });
    }
    if !options.state_directory.is_absolute() {
        return Err(RuntimeError::InvalidInput {
            operation: RuntimeOperation::Initialize,
            field: "state_directory",
            reason: "path must be absolute",
        });
    }
    for (field, value, maximum) in [
        (
            "command_timeout",
            options.command_timeout,
            MAX_ALLOWED_COMMAND_TIMEOUT,
        ),
        (
            "startup_probe_duration",
            options.startup_probe_duration,
            MAX_ALLOWED_COMMAND_TIMEOUT,
        ),
        (
            "stop_timeout",
            options.stop_timeout,
            MAX_ALLOWED_STOP_TIMEOUT,
        ),
    ] {
        if value.is_zero() || value > maximum {
            return Err(RuntimeError::InvalidInput {
                operation: RuntimeOperation::Initialize,
                field,
                reason: "duration is zero or exceeds its hard limit",
            });
        }
    }
    if options.max_config_bytes == 0 || options.max_config_bytes > MAX_ALLOWED_CONFIG_BYTES {
        return Err(RuntimeError::InvalidInput {
            operation: RuntimeOperation::Initialize,
            field: "max_config_bytes",
            reason: "value is zero or exceeds its hard limit",
        });
    }
    if options.max_version_output_bytes == 0
        || options.max_version_output_bytes > MAX_ALLOWED_VERSION_OUTPUT_BYTES
    {
        return Err(RuntimeError::InvalidInput {
            operation: RuntimeOperation::Initialize,
            field: "max_version_output_bytes",
            reason: "value is zero or exceeds its hard limit",
        });
    }
    Ok(())
}

fn ensure_state_directory(path: &Path) -> RuntimeResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(RuntimeError::InvalidInput {
                    operation: RuntimeOperation::Initialize,
                    field: "state_directory",
                    reason: "symbolic links are not accepted",
                });
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.is_dir() && metadata.permissions().mode() & 0o022 != 0 {
                    return Err(RuntimeError::InvalidInput {
                        operation: RuntimeOperation::Initialize,
                        field: "state_directory",
                        reason: "directory is group or world writable",
                    });
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|error| process_io(RuntimeOperation::Initialize, &error))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|error| process_io(RuntimeOperation::Initialize, &error))?;
            }
            Ok(())
        }
        Err(error) => Err(process_io(RuntimeOperation::Initialize, &error)),
    }
}

fn write_private_config(file: &mut File, runtime_json: &str) -> io::Result<()> {
    file.write_all(runtime_json.as_bytes())?;
    file.sync_all()
}

fn run_status_command(
    command: &mut Command,
    config: ManagedConfig,
    cleanup_permit: CleanupPermit,
    operation: RuntimeOperation,
    timeout: Duration,
    stop_timeout: Duration,
    cleanup_reaper: &CleanupReaper,
) -> RuntimeResult<ExitStatus> {
    let mut child = spawn_configured_child(
        command,
        config,
        cleanup_permit,
        operation,
        stop_timeout,
        cleanup_reaper,
    )?;
    let status = match wait_until(child.child_mut()?, timeout, operation) {
        Ok(Some(status)) => status,
        Ok(None) => {
            let timeout_error = RuntimeError::TimedOut {
                operation,
                timeout_ms: duration_millis(timeout, operation)?,
            };
            if child.terminate().is_ok() {
                child.cleanup_config()?;
            }
            return Err(timeout_error);
        }
        Err(error) => {
            if child.terminate().is_ok() {
                child.cleanup_config()?;
            }
            return Err(error);
        }
    };
    child.terminate()?;
    child.cleanup_config()?;
    Ok(status)
}

fn run_bounded_output_command(
    command: &mut Command,
    operation: RuntimeOperation,
    timeout: Duration,
    stop_timeout: Duration,
    limit: usize,
    cleanup_reaper: &CleanupReaper,
) -> RuntimeResult<Vec<u8>> {
    let cleanup_permit = cleanup_reaper.acquire(operation)?;
    let child = command
        .spawn()
        .map_err(|error| unavailable_for_io(operation, &error))?;
    let mut child = ChildGuard::new(
        child,
        None,
        cleanup_permit,
        operation,
        stop_timeout,
        cleanup_reaper,
    )?;
    let stdout = child
        .child_mut()?
        .stdout
        .take()
        .ok_or(RuntimeError::InternalState { operation })?;
    let read_limit = u64::try_from(limit)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or(RuntimeError::InternalState { operation })?;
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("flowprobe-runtime-output".to_owned())
        .spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout
                .take(read_limit)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _send_result = sender.send(result);
        })
        .map_err(|error| process_io(operation, &error))?;

    let started = Instant::now();
    let status = match wait_until(child.child_mut()?, timeout, operation) {
        Ok(Some(status)) => status,
        Ok(None) => {
            let timeout_error = RuntimeError::TimedOut {
                operation,
                timeout_ms: duration_millis(timeout, operation)?,
            };
            let _cleanup_result = child.terminate();
            return Err(timeout_error);
        }
        Err(error) => {
            let _cleanup_result = child.terminate();
            return Err(error);
        }
    };
    child.terminate()?;
    let remaining = timeout.saturating_sub(started.elapsed());
    let bytes = match receiver.recv_timeout(remaining) {
        Ok(result) => result.map_err(|error| process_io(operation, &error))?,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            return Err(RuntimeError::TimedOut {
                operation,
                timeout_ms: duration_millis(timeout, operation)?,
            });
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err(RuntimeError::InternalState { operation });
        }
    };
    if bytes.len() > limit {
        return Err(RuntimeError::OutputLimitExceeded { operation, limit });
    }
    if !status.success() {
        return Err(RuntimeError::ProcessExited {
            operation,
            exit_code: status.code(),
        });
    }
    Ok(bytes)
}

fn wait_until(
    child: &mut Child,
    timeout: Duration,
    operation: RuntimeOperation,
) -> RuntimeResult<Option<ExitStatus>> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) if started.elapsed() >= timeout => return Ok(None),
            Ok(None) => thread::sleep(POLL_INTERVAL.min(timeout.saturating_sub(started.elapsed()))),
            Err(error) => return Err(process_io(operation, &error)),
        }
    }
}

#[cfg(unix)]
fn terminate_managed_child(
    managed: &mut ManagedChild,
    operation: RuntimeOperation,
    timeout: Duration,
) -> RuntimeResult<()> {
    let process_group = managed.process_group;
    let mut leader_reaped = managed
        .child
        .try_wait()
        .map_err(|error| process_io(operation, &error))?
        .is_some();
    let started = Instant::now();
    let graceful_timeout = timeout / 2;
    // Sub-poll budgets hand ownership off promptly; ordinary stops get a fixed
    // scheduler-independent window to reap the leader and observe PGID removal.
    let post_kill_timeout = if timeout < POLL_INTERVAL {
        timeout
    } else {
        POST_SIGKILL_REAP_TIMEOUT
    };
    let mut group_alive = process_group_is_alive(process_group, operation)?;
    let mut kill_sent = false;
    let mut kill_started = None;

    if leader_reaped {
        if group_alive {
            signal_process_group(process_group, operation, Signal::SIGKILL)?;
            kill_sent = true;
            kill_started = Some(Instant::now());
            if post_kill_timeout.is_zero() {
                return Err(termination_timeout(operation, timeout)?);
            }
        }
    } else if group_alive {
        signal_process_group(process_group, operation, Signal::SIGTERM)?;
    }

    loop {
        if !leader_reaped {
            leader_reaped = managed
                .child
                .try_wait()
                .map_err(|error| process_io(operation, &error))?
                .is_some();
        }
        group_alive = process_group_is_alive(process_group, operation)?;
        if leader_reaped && !group_alive {
            return Ok(());
        }

        let elapsed = started.elapsed();
        if !kill_sent && group_alive && (leader_reaped || elapsed >= graceful_timeout) {
            signal_process_group(process_group, operation, Signal::SIGKILL)?;
            kill_sent = true;
            kill_started = Some(Instant::now());
            if post_kill_timeout.is_zero() {
                return Err(termination_timeout(operation, timeout)?);
            }
            continue;
        }
        if let Some(kill_started) = kill_started {
            let kill_elapsed = kill_started.elapsed();
            if kill_elapsed >= post_kill_timeout {
                return Err(termination_timeout(operation, timeout)?);
            }
            thread::sleep(POLL_INTERVAL.min(post_kill_timeout.saturating_sub(kill_elapsed)));
        } else {
            if elapsed >= timeout {
                return Err(termination_timeout(operation, timeout)?);
            }
            thread::sleep(POLL_INTERVAL.min(timeout.saturating_sub(elapsed)));
        }
    }
}

#[cfg(not(unix))]
fn terminate_managed_child(
    managed: &mut ManagedChild,
    operation: RuntimeOperation,
    timeout: Duration,
) -> RuntimeResult<()> {
    let child = &mut managed.child;
    if child
        .try_wait()
        .map_err(|error| process_io(operation, &error))?
        .is_some()
    {
        return Ok(());
    }

    child
        .kill()
        .map_err(|error| process_io(operation, &error))?;
    if wait_until(child, timeout, operation)?.is_some() {
        Ok(())
    } else {
        Err(RuntimeError::TimedOut {
            operation,
            timeout_ms: duration_millis(timeout, operation)?,
        })
    }
}

fn cleanup_active_config(
    state: &mut ManagedState,
    operation: RuntimeOperation,
) -> RuntimeResult<()> {
    let Some(config) = state.active_config.as_mut() else {
        if state.child.is_none() {
            state.cleanup_permit = None;
        }
        return Ok(());
    };
    config.cleanup(operation)?;
    state.active_config = None;
    if state.child.is_none() {
        state.cleanup_permit = None;
    }
    Ok(())
}

#[cfg(unix)]
fn signal_process_group(
    process_group: Pid,
    operation: RuntimeOperation,
    signal: Signal,
) -> RuntimeResult<()> {
    match killpg(process_group, signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(Errno::EPERM) => Err(RuntimeError::Unavailable {
            operation,
            reason: flowprobe_runtime_api::RuntimeUnavailableReason::PermissionDenied,
        }),
        Err(_) => Err(RuntimeError::ProcessIo {
            operation,
            kind: ProcessIoKind::Other,
        }),
    }
}

#[cfg(unix)]
fn process_group_is_alive(process_group: Pid, operation: RuntimeOperation) -> RuntimeResult<bool> {
    match killpg(process_group, None) {
        Ok(()) | Err(Errno::EPERM) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(_) => Err(RuntimeError::ProcessIo {
            operation,
            kind: ProcessIoKind::Other,
        }),
    }
}

fn duration_millis(duration: Duration, operation: RuntimeOperation) -> RuntimeResult<u64> {
    u64::try_from(duration.as_millis().max(1))
        .map_err(|_| RuntimeError::InternalState { operation })
}

fn termination_timeout(
    operation: RuntimeOperation,
    timeout: Duration,
) -> RuntimeResult<RuntimeError> {
    Ok(RuntimeError::TimedOut {
        operation,
        timeout_ms: duration_millis(timeout, operation)?,
    })
}

fn health_for_state(state: &RuntimeState) -> RuntimeHealth {
    match state {
        RuntimeState::Stopped { .. } => RuntimeHealth::Inactive,
        RuntimeState::Running { .. } => RuntimeHealth::Healthy,
        RuntimeState::Crashed { exit_code, .. } => RuntimeHealth::Unhealthy {
            exit_code: *exit_code,
        },
    }
}

fn process_io(operation: RuntimeOperation, error: &io::Error) -> RuntimeError {
    RuntimeError::ProcessIo {
        operation,
        kind: error.kind().into(),
    }
}

fn unavailable_for_io(operation: RuntimeOperation, error: &io::Error) -> RuntimeError {
    use flowprobe_runtime_api::RuntimeUnavailableReason;

    let reason = match error.kind() {
        io::ErrorKind::NotFound => RuntimeUnavailableReason::ExecutableMissing,
        io::ErrorKind::PermissionDenied => RuntimeUnavailableReason::PermissionDenied,
        _ => RuntimeUnavailableReason::Other,
    };
    RuntimeError::Unavailable { operation, reason }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    static NEXT_CONFIG_CLEANUP_TEST: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    struct CleanupTestDirectory(PathBuf);

    impl CleanupTestDirectory {
        fn new() -> Self {
            let unique =
                NEXT_CONFIG_CLEANUP_TEST.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "flowprobe-config-cleanup-test-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("unique cleanup test directory should be created");
            Self(path)
        }
    }

    impl Drop for CleanupTestDirectory {
        fn drop(&mut self) {
            let _cleanup_result = fs::remove_dir_all(&self.0);
        }
    }

    fn wait_for_worker_exit(queue: &CleanupQueue) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if !lock_cleanup_queue(queue).worker_running {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "cleanup worker did not stop after all ownership returned"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn cleanup_capacity_rejects_before_spawn_and_worker_exits_after_permits_return() {
        let reaper = CleanupReaper::new().expect("cleanup reaper should start");
        let queue = Arc::clone(&reaper.queue);
        let permits = (0..CLEANUP_REAPER_CAPACITY)
            .map(|_| {
                reaper
                    .acquire(RuntimeOperation::Version)
                    .expect("capacity permit should be available")
            })
            .collect::<Vec<_>>();

        assert_eq!(lock_cleanup_queue(&queue).owned, CLEANUP_REAPER_CAPACITY);
        assert!(matches!(
            reaper.acquire(RuntimeOperation::Version),
            Err(RuntimeError::Unavailable {
                operation: RuntimeOperation::Version,
                reason: flowprobe_runtime_api::RuntimeUnavailableReason::Other,
            })
        ));
        let mut command = Command::new("__flowprobe_missing_cleanup_capacity_probe__");
        command.stdout(Stdio::piped()).stderr(Stdio::null());
        assert!(matches!(
            run_bounded_output_command(
                &mut command,
                RuntimeOperation::Version,
                Duration::from_millis(10),
                Duration::from_millis(10),
                16,
                &reaper,
            ),
            Err(RuntimeError::Unavailable {
                operation: RuntimeOperation::Version,
                reason: flowprobe_runtime_api::RuntimeUnavailableReason::Other,
            })
        ));

        drop(reaper);
        assert!(lock_cleanup_queue(&queue).worker_running);
        drop(permits);
        wait_for_worker_exit(&queue);
        assert_eq!(lock_cleanup_queue(&queue).owned, 0);
    }

    #[test]
    fn config_capacity_rejects_validate_and_start_before_writing() {
        let directory = CleanupTestDirectory::new();
        let state_directory = directory.0.join("state");
        let runtime = SingBoxRuntime::new(SingBoxOptions {
            executable: std::env::current_exe().expect("test executable should be discoverable"),
            state_directory: state_directory.clone(),
            command_timeout: Duration::from_secs(1),
            startup_probe_duration: Duration::from_millis(10),
            stop_timeout: Duration::from_millis(10),
            max_config_bytes: 1024,
            max_version_output_bytes: 1024,
        })
        .expect("runtime should initialize for capacity testing");
        let queue = Arc::clone(&runtime.cleanup_reaper.queue);
        let permits = (0..CLEANUP_REAPER_CAPACITY)
            .map(|_| {
                runtime
                    .cleanup_reaper
                    .acquire(RuntimeOperation::Start)
                    .expect("capacity permit should be available")
            })
            .collect::<Vec<_>>();

        for operation in [RuntimeOperation::ValidateConfig, RuntimeOperation::Start] {
            assert!(matches!(
                runtime.prepare_config("{}", operation),
                Err(RuntimeError::Unavailable {
                    operation: actual,
                    reason: flowprobe_runtime_api::RuntimeUnavailableReason::Other,
                }) if actual == operation
            ));
            assert_eq!(
                fs::read_dir(&state_directory)
                    .expect("state directory should remain readable")
                    .count(),
                0,
                "capacity rejection must happen before config creation"
            );
        }

        drop(permits);
        drop(runtime);
        wait_for_worker_exit(&queue);
        assert_eq!(lock_cleanup_queue(&queue).owned, 0);
    }

    #[test]
    fn cleanup_worker_drains_pending_work_after_reaper_shutdown() {
        let reaper = CleanupReaper::new().expect("cleanup reaper should start");
        let queue = Arc::clone(&reaper.queue);
        let permit = reaper
            .acquire(RuntimeOperation::Version)
            .expect("cleanup permit should be available");
        reaper.handoff(PendingCleanup::new(
            None,
            Some(ManagedConfig {
                path: PathBuf::new(),
                runtime_json: String::new(),
            }),
            Some(permit),
            RuntimeOperation::Version,
        ));

        drop(reaper);
        wait_for_worker_exit(&queue);
        let state = lock_cleanup_queue(&queue);
        assert_eq!(state.owned, 0);
        assert!(state.pending.is_empty());
    }

    #[test]
    fn config_spawn_failure_handoff_retries_and_returns_its_cleanup_permit() {
        let directory = CleanupTestDirectory::new();
        let config_path = directory.0.join("managed-config");
        fs::create_dir(&config_path)
            .expect("a directory at the config path should make remove_file fail");
        let reaper = CleanupReaper::new().expect("cleanup reaper should start");
        let queue = Arc::clone(&reaper.queue);
        let permit = reaper
            .acquire(RuntimeOperation::Start)
            .expect("cleanup permit should be available");

        let mut command = Command::new("__flowprobe_missing_config_cleanup_probe__");
        let error = match spawn_configured_child(
            &mut command,
            ManagedConfig {
                path: config_path.clone(),
                runtime_json: String::new(),
            },
            permit,
            RuntimeOperation::Start,
            Duration::from_millis(10),
            &reaper,
        ) {
            Ok(_) => panic!("missing executable must not spawn"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            RuntimeError::Unavailable {
                operation: RuntimeOperation::Start,
                reason: flowprobe_runtime_api::RuntimeUnavailableReason::ExecutableMissing,
            }
        );

        let deadline = Instant::now() + Duration::from_secs(2);
        let state = loop {
            let state = lock_cleanup_queue(&queue);
            if !state.pending.is_empty() {
                break state;
            }
            drop(state);
            assert!(
                Instant::now() < deadline,
                "config-only cleanup was not retained for retry"
            );
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(state.owned, 1);
        assert!(state.worker_running);
        fs::remove_dir(&config_path).expect("blocking directory should be removable");
        fs::write(&config_path, b"private config")
            .expect("retry should receive a removable regular file at the same path");
        drop(state);

        drop(reaper);
        wait_for_worker_exit(&queue);
        let state = lock_cleanup_queue(&queue);
        assert_eq!(state.owned, 0);
        assert!(state.pending.is_empty());
        assert!(!config_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn child_guard_drop_transfers_process_group_ownership_to_the_worker() {
        let reaper = CleanupReaper::new().expect("cleanup reaper should start");
        let queue = Arc::clone(&reaper.queue);
        let permit = reaper
            .acquire(RuntimeOperation::Version)
            .expect("cleanup permit should be available");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("while :; do sleep 1; done")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let child = command.spawn().expect("fixture child should spawn");
        let process_group =
            Pid::from_raw(i32::try_from(child.id()).expect("Unix process id should fit in pid_t"));
        let guard = ChildGuard::new(
            child,
            None,
            permit,
            RuntimeOperation::Version,
            Duration::from_nanos(1),
            &reaper,
        )
        .expect("child guard should own the process");

        drop(guard);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if !process_group_is_alive(process_group, RuntimeOperation::Version)
                .expect("process-group liveness should be queryable")
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "cleanup worker did not reclaim ChildGuard drop"
            );
            thread::sleep(Duration::from_millis(10));
        }
        drop(reaper);
        wait_for_worker_exit(&queue);
    }
}
