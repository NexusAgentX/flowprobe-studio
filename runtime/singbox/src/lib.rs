//! Thin managed-process adapter for the documented sing-box CLI.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Mutex, MutexGuard, mpsc},
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

const MAX_CONFIG_CREATE_ATTEMPTS: usize = 32;
const MAX_ALLOWED_CONFIG_BYTES: usize = 8 * 1024 * 1024;
const MAX_ALLOWED_VERSION_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_ALLOWED_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ALLOWED_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

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
}

struct ManagedState {
    runtime_state: RuntimeState,
    child: Option<Child>,
    active_config: Option<ManagedConfig>,
}

struct ManagedConfig {
    path: PathBuf,
    runtime_json: String,
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
        if !self.path.as_os_str().is_empty() {
            let _remove_result = fs::remove_file(&self.path);
        }
    }
}

struct ChildGuard {
    child: Option<Child>,
    operation: RuntimeOperation,
    stop_timeout: Duration,
}

impl ChildGuard {
    fn new(child: Child, operation: RuntimeOperation, stop_timeout: Duration) -> Self {
        Self {
            child: Some(child),
            operation,
            stop_timeout,
        }
    }

    fn child_mut(&mut self) -> RuntimeResult<&mut Child> {
        self.child.as_mut().ok_or(RuntimeError::InternalState {
            operation: self.operation,
        })
    }

    fn disarm(&mut self) {
        self.child = None;
    }

    fn into_child(mut self) -> RuntimeResult<Child> {
        self.child.take().ok_or(RuntimeError::InternalState {
            operation: self.operation,
        })
    }

    fn terminate(&mut self) -> RuntimeResult<()> {
        if let Some(child) = self.child.as_mut() {
            terminate_child(child, self.operation, self.stop_timeout)?;
            self.child = None;
        }
        Ok(())
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _termination_result = self.terminate();
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
            }),
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
    ) -> RuntimeResult<ManagedConfig> {
        if runtime_json.len() > self.max_config_bytes {
            return Err(RuntimeError::InvalidInput {
                operation,
                field: "compiled_config",
                reason: "configuration exceeds its byte limit",
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
                    let mut config = ManagedConfig {
                        path,
                        runtime_json: runtime_json.to_owned(),
                    };
                    if let Err(error) = write_private_config(&mut file, runtime_json) {
                        drop(file);
                        config.cleanup(operation)?;
                        return Err(process_io(operation, &error));
                    }
                    return Ok(config);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(process_io(operation, &error)),
            }
        }
        Err(RuntimeError::ProcessIo {
            operation,
            kind: ProcessIoKind::AlreadyExists,
        })
    }

    fn check_runtime_json(&self, runtime_json: &str) -> RuntimeResult<()> {
        let mut config = self.write_config(runtime_json, RuntimeOperation::ValidateConfig)?;
        let mut command = self.configured_command(&config.path, "check");
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let result = run_status_command(
            &mut command,
            RuntimeOperation::ValidateConfig,
            self.command_timeout,
            self.stop_timeout,
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
        });
        config.cleanup(RuntimeOperation::ValidateConfig)?;
        result
    }

    fn refresh_locked(state: &mut ManagedState, operation: RuntimeOperation) -> RuntimeResult<()> {
        let Some(child) = state.child.as_mut() else {
            if state.runtime_state.phase() != RuntimePhase::Running {
                cleanup_active_config(state, operation)?;
            }
            return Ok(());
        };
        match child.try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => {
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
        Self::refresh_locked(&mut state, RuntimeOperation::Start)?;
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

        self.check_runtime_json(config.runtime_json())?;
        let mut managed_config =
            self.write_config(config.runtime_json(), RuntimeOperation::Start)?;
        let mut command = self.configured_command(&managed_config.path, "run");
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                managed_config.cleanup(RuntimeOperation::Start)?;
                return Err(unavailable_for_io(RuntimeOperation::Start, &error));
            }
        };
        let mut child = ChildGuard::new(child, RuntimeOperation::Start, self.stop_timeout);
        let startup_result = wait_until(
            child.child_mut()?,
            self.startup_probe_duration,
            RuntimeOperation::Start,
        );
        let startup_status = match startup_result {
            Ok(status) => status,
            Err(error) => {
                managed_config.cleanup(RuntimeOperation::Start)?;
                return Err(error);
            }
        };
        if let Some(status) = startup_status {
            child.disarm();
            managed_config.cleanup(RuntimeOperation::Start)?;
            return Err(RuntimeError::ProcessExited {
                operation: RuntimeOperation::Start,
                exit_code: status.code(),
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
        let process_id = child.child_mut()?.id();
        state.child = Some(child.into_child()?);
        state.active_config = Some(managed_config);
        state.runtime_state = RuntimeState::Running {
            generation,
            process_id: Some(process_id),
        };
        Ok(state.runtime_state.clone())
    }

    fn stop(&self) -> RuntimeResult<RuntimeState> {
        let mut state = self.lock(RuntimeOperation::Stop)?;
        Self::refresh_locked(&mut state, RuntimeOperation::Stop)?;
        let generation = state.runtime_state.generation();
        let Some(mut child) = state.child.take() else {
            state.runtime_state = RuntimeState::Stopped { generation };
            cleanup_active_config(&mut state, RuntimeOperation::Stop)?;
            return Ok(state.runtime_state.clone());
        };
        if let Err(error) = terminate_child(&mut child, RuntimeOperation::Stop, self.stop_timeout) {
            state.child = Some(child);
            return Err(error);
        }
        state.runtime_state = RuntimeState::Stopped { generation };
        cleanup_active_config(&mut state, RuntimeOperation::Stop)?;
        Ok(state.runtime_state.clone())
    }

    fn health(&self) -> RuntimeResult<RuntimeHealth> {
        let mut state = self.lock(RuntimeOperation::Health)?;
        Self::refresh_locked(&mut state, RuntimeOperation::Health)?;
        Ok(health_for_state(&state.runtime_state))
    }

    fn state(&self) -> RuntimeResult<RuntimeState> {
        let mut state = self.lock(RuntimeOperation::State)?;
        Self::refresh_locked(&mut state, RuntimeOperation::State)?;
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
        Self::refresh_locked(&mut state, RuntimeOperation::Status)?;
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
        let Ok(state) = self.state.get_mut() else {
            return;
        };
        if let Some(mut child) = state.child.take() {
            let _termination_result =
                terminate_child(&mut child, RuntimeOperation::Stop, self.stop_timeout);
        }
        if let Some(config) = state.active_config.as_mut() {
            let _cleanup_result = config.cleanup(RuntimeOperation::Stop);
        }
        state.active_config = None;
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
    operation: RuntimeOperation,
    timeout: Duration,
    stop_timeout: Duration,
) -> RuntimeResult<ExitStatus> {
    let child = command
        .spawn()
        .map_err(|error| unavailable_for_io(operation, &error))?;
    let mut child = ChildGuard::new(child, operation, stop_timeout);
    if let Some(status) = wait_until(child.child_mut()?, timeout, operation)? {
        child.disarm();
        return Ok(status);
    }
    let timeout_error = RuntimeError::TimedOut {
        operation,
        timeout_ms: duration_millis(timeout, operation)?,
    };
    child.terminate()?;
    Err(timeout_error)
}

fn run_bounded_output_command(
    command: &mut Command,
    operation: RuntimeOperation,
    timeout: Duration,
    stop_timeout: Duration,
    limit: usize,
) -> RuntimeResult<Vec<u8>> {
    let child = command
        .spawn()
        .map_err(|error| unavailable_for_io(operation, &error))?;
    let mut child = ChildGuard::new(child, operation, stop_timeout);
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
    let status = match wait_until(child.child_mut()?, timeout, operation)? {
        Some(status) => status,
        None => {
            let timeout_error = RuntimeError::TimedOut {
                operation,
                timeout_ms: duration_millis(timeout, operation)?,
            };
            child.terminate()?;
            return Err(timeout_error);
        }
    };
    let remaining = timeout.saturating_sub(started.elapsed());
    let bytes = match receiver.recv_timeout(remaining) {
        Ok(result) => result.map_err(|error| process_io(operation, &error))?,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            force_remaining_process_group(child.child_mut()?, operation)?;
            child.disarm();
            return Err(RuntimeError::TimedOut {
                operation,
                timeout_ms: duration_millis(timeout, operation)?,
            });
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            child.disarm();
            return Err(RuntimeError::InternalState { operation });
        }
    };
    child.disarm();
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

fn terminate_child(
    child: &mut Child,
    operation: RuntimeOperation,
    timeout: Duration,
) -> RuntimeResult<()> {
    if child
        .try_wait()
        .map_err(|error| process_io(operation, &error))?
        .is_some()
    {
        return Ok(());
    }

    let started = Instant::now();
    send_termination(child, operation)?;
    let graceful_timeout = timeout / 2;
    if wait_until(child, graceful_timeout, operation)?.is_some() {
        return Ok(());
    }
    force_termination(child, operation)?;
    let remaining = timeout.saturating_sub(started.elapsed());
    if wait_until(child, remaining, operation)?.is_some() {
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
        return Ok(());
    };
    config.cleanup(operation)?;
    state.active_config = None;
    Ok(())
}

#[cfg(unix)]
fn send_termination(child: &mut Child, operation: RuntimeOperation) -> RuntimeResult<()> {
    signal_process_group(child, operation, Signal::SIGTERM)
}

#[cfg(not(unix))]
fn send_termination(child: &mut Child, operation: RuntimeOperation) -> RuntimeResult<()> {
    child.kill().map_err(|error| process_io(operation, &error))
}

#[cfg(unix)]
fn force_termination(child: &mut Child, operation: RuntimeOperation) -> RuntimeResult<()> {
    signal_process_group(child, operation, Signal::SIGKILL)
}

#[cfg(not(unix))]
fn force_termination(child: &mut Child, operation: RuntimeOperation) -> RuntimeResult<()> {
    child.kill().map_err(|error| process_io(operation, &error))
}

#[cfg(unix)]
fn signal_process_group(
    child: &Child,
    operation: RuntimeOperation,
    signal: Signal,
) -> RuntimeResult<()> {
    let process_id =
        i32::try_from(child.id()).map_err(|_| RuntimeError::InternalState { operation })?;
    match killpg(Pid::from_raw(process_id), signal) {
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
fn force_remaining_process_group(child: &Child, operation: RuntimeOperation) -> RuntimeResult<()> {
    signal_process_group(child, operation, Signal::SIGKILL)
}

#[cfg(not(unix))]
fn force_remaining_process_group(
    _child: &Child,
    _operation: RuntimeOperation,
) -> RuntimeResult<()> {
    Ok(())
}

fn duration_millis(duration: Duration, operation: RuntimeOperation) -> RuntimeResult<u64> {
    u64::try_from(duration.as_millis()).map_err(|_| RuntimeError::InternalState { operation })
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
