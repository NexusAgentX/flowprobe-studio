use std::{
    env,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
    time::Duration,
};

use flowprobe_config_compiler::{ConfigCompiler, RuntimeOverlay, SystemBase, UserProfile};
use flowprobe_runtime_api::{
    NetworkRuntime, RuntimeCapability, RuntimeHealth, RuntimePhase, RuntimeState,
};
use flowprobe_singbox_runtime::{SingBoxOptions, SingBoxRuntime};
use flowprobe_supervisor::Supervisor;
use serde_json::{Value, json};

const EXPECTED_RUNTIME_VERSION: &str = "sing-box version 1.13.19";
const PROOF_HEADER: &str = "X-FlowProbe-Proof: INT001-LOOPBACK-PROOF";
const SYSTEM_CONFIG: &str = r#"{
  "log": {"level": "warn", "timestamp": false},
  "inbounds": [{
    "type": "http",
    "tag": "__flowprobe_loopback_http",
    "listen": "127.0.0.1",
    "listen_port": 0,
    "set_system_proxy": false
  }],
  "outbounds": [{"type": "direct", "tag": "__flowprobe_direct"}],
  "route": {"final": "__flowprobe_direct"}
}"#;

struct RuntimeCleanup {
    runtime: Arc<SingBoxRuntime>,
    pid_file: PathBuf,
    armed: bool,
}

impl Drop for RuntimeCleanup {
    fn drop(&mut self) {
        if self.armed && self.runtime.stop().is_ok() {
            // A successful stop makes the recorded process group stale. On a
            // stop failure, retain it so the Python parent can perform its
            // bounded, exact-process-group fallback cleanup.
            let _remove_result = fs::remove_file(&self.pid_file);
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let sing_box = absolute_file_from_env("FLOWPROBE_SING_BOX_BIN")?;
    let curl = absolute_file_from_env("FLOWPROBE_CURL_BIN")?;
    let state_directory = absolute_path_from_env("FLOWPROBE_V0_1_STATE_DIR")?;
    let pid_file = absolute_path_from_env("FLOWPROBE_V0_1_RUNTIME_PID_FILE")?;
    require(
        pid_file.parent() == Some(state_directory.as_path()),
        "runtime PID file must be directly inside the temporary state directory",
    )?;
    let certificate = absolute_file_from_env("FLOWPROBE_V0_1_TLS_CERT")?;
    let proxy_port = parse_port_from_env("FLOWPROBE_V0_1_PROXY_PORT")?;
    let http_url = loopback_url_from_env("FLOWPROBE_V0_1_HTTP_URL", "http")?;
    let https_url = loopback_url_from_env("FLOWPROBE_V0_1_HTTPS_URL", "https")?;
    let expected_http = required_env("FLOWPROBE_V0_1_HTTP_EXPECTED")?;
    let expected_https = required_env("FLOWPROBE_V0_1_HTTPS_EXPECTED")?;

    let runtime = Arc::new(SingBoxRuntime::new(SingBoxOptions {
        executable: sing_box,
        state_directory: state_directory.clone(),
        command_timeout: Duration::from_secs(10),
        startup_probe_duration: Duration::from_secs(2),
        stop_timeout: Duration::from_secs(5),
        max_config_bytes: 1024 * 1024,
        max_version_output_bytes: 64 * 1024,
    })?);
    let mut cleanup = RuntimeCleanup {
        runtime: Arc::clone(&runtime),
        pid_file: pid_file.clone(),
        armed: true,
    };

    let overlay = RuntimeOverlay::parse(
        &json!({
            "inbounds": [{
                "tag": "__flowprobe_loopback_http",
                "listen_port": proxy_port,
            }]
        })
        .to_string(),
    )?;
    let compiled = ConfigCompiler::new(runtime.as_ref()).compile(
        &SystemBase::parse(SYSTEM_CONFIG)?,
        &UserProfile::parse("{}")?,
        &overlay,
    )?;
    validate_local_only_config(compiled.runtime_json(), proxy_port)?;
    require(
        managed_config_count(&state_directory)? == 0,
        "compiler check must remove its temporary managed configuration",
    )?;

    let network: Arc<dyn NetworkRuntime> = runtime.clone();
    let supervisor = Supervisor::with_network_runtime(network);
    supervisor.validate_network_config(&compiled)?;
    require(
        managed_config_count(&state_directory)? == 0,
        "explicit check must remove its temporary managed configuration",
    )?;

    let version = supervisor.network_version()?;
    require(
        version.as_str() == EXPECTED_RUNTIME_VERSION,
        &format!(
            "runtime API version mismatch: expected {EXPECTED_RUNTIME_VERSION:?}, got {:?}",
            version.as_str()
        ),
    )?;
    let capabilities = supervisor.network_capabilities()?;
    for capability in [
        RuntimeCapability::ConfigValidation,
        RuntimeCapability::ProcessLifecycle,
        RuntimeCapability::Health,
        RuntimeCapability::Version,
        RuntimeCapability::DirectEgress,
        RuntimeCapability::RuntimeStatus,
    ] {
        require(
            capabilities.supports(capability),
            &format!("runtime is missing required capability {capability:?}"),
        )?;
    }
    require(
        !capabilities.supports(RuntimeCapability::DirectEgressProbe),
        "this proof must not pretend that the adapter provides a direct-egress probe",
    )?;

    let started = supervisor.start_network_runtime(&compiled)?;
    require(
        started.phase() == RuntimePhase::Running,
        "runtime did not enter running phase",
    )?;
    let process_id = match &started {
        RuntimeState::Running {
            process_id: Some(process_id),
            ..
        } => *process_id,
        _ => {
            return Err(io::Error::other(
                "real runtime did not report its managed process identity",
            )
            .into());
        }
    };
    fs::write(&pid_file, process_id.to_string())?;
    require(
        supervisor.network_health()? == RuntimeHealth::Healthy,
        "running runtime did not report healthy",
    )?;
    let running_status = supervisor.network_status()?;
    require(
        running_status.state.phase() == RuntimePhase::Running
            && running_status.health == RuntimeHealth::Healthy,
        "runtime status did not report running and healthy",
    )?;
    require(
        managed_config_count(&state_directory)? == 1,
        "running runtime must own exactly one managed configuration",
    )?;

    let curl_result = prove_origins_through_proxy(
        &curl,
        proxy_port,
        &http_url,
        &https_url,
        &certificate,
        &expected_http,
        &expected_https,
    );
    let stop_result = supervisor.stop_network_runtime();
    let stopped_status_result = supervisor.network_status();
    let remaining_configs_result = managed_config_count(&state_directory);

    let stopped = stop_result?;
    require(
        stopped
            == (RuntimeState::Stopped {
                generation: started.generation(),
            }),
        "stop did not preserve the active runtime generation",
    )?;
    let stopped_status = stopped_status_result?;
    require(
        stopped_status.state.phase() == RuntimePhase::Stopped
            && stopped_status.health == RuntimeHealth::Inactive,
        "runtime status did not report stopped and inactive",
    )?;
    require(
        remaining_configs_result? == 0,
        "stop must remove every managed runtime configuration",
    )?;
    curl_result?;
    fs::remove_file(&pid_file)?;
    cleanup.armed = false;

    println!("runtime-version={}", version.as_str());
    println!("config-validation=compiler-check,explicit-check");
    println!("runtime-lifecycle=start,healthy,status,stop,stopped");
    println!("proxy=http://127.0.0.1:{proxy_port}");
    println!("http-origin={http_url}");
    println!("https-origin={https_url}");
    println!("managed-configs-after-stop=0");
    println!("runtime-pid-file-after-stop=removed");
    println!("local-network-proof=passed");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prove_origins_through_proxy(
    curl: &Path,
    proxy_port: u16,
    http_url: &str,
    https_url: &str,
    certificate: &Path,
    expected_http: &str,
    expected_https: &str,
) -> io::Result<()> {
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    let http = run_curl(curl, &proxy, http_url, None)?;
    require_output(http, "HTTP", expected_http)?;
    let https = run_curl(curl, &proxy, https_url, Some(certificate))?;
    require_output(https, "HTTPS", expected_https)
}

fn run_curl(curl: &Path, proxy: &str, url: &str, certificate: Option<&Path>) -> io::Result<Output> {
    build_curl_command(curl, proxy, url, certificate).output()
}

fn build_curl_command(curl: &Path, proxy: &str, url: &str, certificate: Option<&Path>) -> Command {
    let mut command = Command::new(curl);
    // curl only treats --disable as a curlrc opt-out when it is the first
    // argument. Keep it ahead of every transport and trust assertion.
    command.arg("--disable");
    command.args([
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        "10",
        "--noproxy",
        "",
        "--proxy",
        proxy,
        "--header",
        PROOF_HEADER,
    ]);
    if let Some(certificate) = certificate {
        command.arg("--cacert").arg(certificate);
    }
    command.arg(url);
    command
}

fn require_output(output: Output, label: &str, expected: &str) -> io::Result<()> {
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{label} curl failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let body = String::from_utf8(output.stdout).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} origin returned non-UTF-8 proof body"),
        )
    })?;
    require(
        body == expected,
        &format!("{label} origin body did not match the local proof canary"),
    )
}

fn validate_local_only_config(runtime_json: &str, proxy_port: u16) -> io::Result<()> {
    let value: Value = serde_json::from_str(runtime_json).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "compiled runtime configuration is not JSON",
        )
    })?;
    let inbounds = value["inbounds"]
        .as_array()
        .ok_or_else(|| invalid_config("inbounds must be an array"))?;
    let outbounds = value["outbounds"]
        .as_array()
        .ok_or_else(|| invalid_config("outbounds must be an array"))?;
    require(
        inbounds.len() == 1
            && inbounds[0]["type"] == "http"
            && inbounds[0]["tag"] == "__flowprobe_loopback_http"
            && inbounds[0]["listen"] == "127.0.0.1"
            && inbounds[0]["listen_port"] == proxy_port
            && inbounds[0]["set_system_proxy"] == false,
        "compiled inbound must be one loopback HTTP proxy with system proxy disabled",
    )?;
    require(
        outbounds.len() == 1
            && outbounds[0]["type"] == "direct"
            && outbounds[0]["tag"] == "__flowprobe_direct"
            && outbounds[0]
                .as_object()
                .is_some_and(|object| object.len() == 2),
        "compiled outbound must be one address-free direct outbound",
    )?;
    require(
        value["route"]["final"] == "__flowprobe_direct",
        "compiled route must terminate at the protected direct outbound",
    )?;
    reject_forbidden_network_features(&value)
}

fn reject_forbidden_network_features(value: &Value) -> io::Result<()> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                require(
                    key != "auto_route" && key != "auto_redirect",
                    "TUN/global-routing keys are forbidden in the local proof",
                )?;
                if key == "set_system_proxy" {
                    require(
                        child == &Value::Bool(false),
                        "the local proof must not alter the system proxy",
                    )?;
                }
                reject_forbidden_network_features(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_forbidden_network_features(child)?;
            }
        }
        Value::String(text) => {
            require(
                text != "tun",
                "a TUN object is forbidden in the local proof",
            )?;
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn managed_config_count(state_directory: &Path) -> io::Result<usize> {
    let mut count = 0usize;
    for entry in fs::read_dir(state_directory)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(".flowprobe-runtime-"))
        {
            count = count
                .checked_add(1)
                .ok_or_else(|| io::Error::other("managed configuration count overflow"))?;
        }
    }
    Ok(count)
}

fn absolute_file_from_env(name: &str) -> io::Result<PathBuf> {
    let path = absolute_path_from_env(name)?;
    require(
        path.is_file(),
        &format!("{name} must name an existing regular file"),
    )?;
    Ok(path)
}

fn absolute_path_from_env(name: &str) -> io::Result<PathBuf> {
    let path = PathBuf::from(required_env(name)?);
    require(
        path.is_absolute(),
        &format!("{name} must be an absolute path"),
    )?;
    Ok(path)
}

fn loopback_url_from_env(name: &str, scheme: &str) -> io::Result<String> {
    let value = required_env(name)?;
    require(
        value.starts_with(&format!("{scheme}://127.0.0.1:"))
            && !value.contains('@')
            && !value.contains("localhost"),
        &format!("{name} must be an explicit IPv4-loopback {scheme} URL"),
    )?;
    Ok(value)
}

fn parse_port_from_env(name: &str) -> io::Result<u16> {
    let value = required_env(name)?;
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be a non-zero TCP port"),
            )
        })
}

fn required_env(name: &str) -> io::Result<String> {
    env::var(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("required environment variable {name} is missing or non-Unicode"),
        )
    })
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message.to_owned()))
    }
}

fn invalid_config(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::{OsStr, OsString},
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        process,
        sync::atomic::{AtomicU64, Ordering},
        thread::{self, JoinHandle},
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    const HOSTILE_CANARY: &str = "FLOWPROBE_CURLRC_CANARY";
    const HOSTILE_HEADER: &str = "X-FlowProbe-Hostile-Curlrc: loaded";
    const RESPONSE_BODY: &str = "FLOWPROBE_HERMETIC_CURL_BODY";
    const SERVER_DEADLINE: Duration = Duration::from_secs(5);
    const MAX_REQUEST_BYTES: usize = 32 * 1024;
    static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct HostileCurlEnvironment {
        root: PathBuf,
        home: PathBuf,
        curl_home: PathBuf,
        xdg_config_home: PathBuf,
        user_profile: PathBuf,
        app_data: PathBuf,
        cleaned: bool,
    }

    impl HostileCurlEnvironment {
        fn create() -> io::Result<Self> {
            let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos();
            let root = env::temp_dir().join(format!(
                "flowprobe-int-002-curlrc-{}-{nanos}-{sequence}",
                process::id()
            ));
            fs::create_dir(&root)?;

            let environment = Self {
                home: root.join("home"),
                curl_home: root.join("curl-home"),
                xdg_config_home: root.join("xdg-config-home"),
                user_profile: root.join("user-profile"),
                app_data: root.join("app-data"),
                root,
                cleaned: false,
            };
            let config = format!(
                "insecure\nwrite-out = \"{HOSTILE_CANARY}\"\nheader = \"{HOSTILE_HEADER}\"\n"
            );
            for directory in environment.directories() {
                fs::create_dir(directory)?;
                for file_name in [".curlrc", "_curlrc", "curlrc"] {
                    fs::write(directory.join(file_name), &config)?;
                }
            }
            Ok(environment)
        }

        fn directories(&self) -> [&Path; 5] {
            [
                &self.home,
                &self.curl_home,
                &self.xdg_config_home,
                &self.user_profile,
                &self.app_data,
            ]
        }

        fn apply_to(&self, command: &mut Command) {
            command
                .env("HOME", &self.home)
                .env("CURL_HOME", &self.curl_home)
                .env("XDG_CONFIG_HOME", &self.xdg_config_home)
                .env("USERPROFILE", &self.user_profile)
                .env("APPDATA", &self.app_data);
        }

        fn cleanup(&mut self) -> io::Result<()> {
            fs::remove_dir_all(&self.root)?;
            require(
                !self.root.exists(),
                "hostile curl environment remained after explicit cleanup",
            )?;
            self.cleaned = true;
            Ok(())
        }
    }

    impl Drop for HostileCurlEnvironment {
        fn drop(&mut self) {
            if !self.cleaned && self.root.exists() {
                eprintln!(
                    "hostile curl environment was not explicitly cleaned; applying fallback: {}",
                    self.root.display()
                );
                if let Err(error) = fs::remove_dir_all(&self.root) {
                    eprintln!(
                        "failed to remove hostile curl environment {}: {error}",
                        self.root.display()
                    );
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    enum DisableMutation {
        None,
        Remove,
        MoveToSecond,
    }

    #[test]
    fn curl_builder_disables_user_configuration_before_every_other_argument() {
        let http = build_curl_command(
            Path::new("curl"),
            "http://127.0.0.1:41001",
            "http://127.0.0.1:41002/proof",
            None,
        );
        assert_eq!(http.get_args().next(), Some(OsStr::new("--disable")));
        assert_eq!(
            http.get_args()
                .filter(|argument| *argument == OsStr::new("--disable"))
                .count(),
            1
        );
        assert!(!http.get_args().any(|argument| argument == "--cacert"));

        let certificate = Path::new("flowprobe-int-002-origin.crt");
        let https = build_curl_command(
            Path::new("curl"),
            "http://127.0.0.1:41001",
            "https://127.0.0.1:41003/proof",
            Some(certificate),
        );
        let https_arguments = https.get_args().collect::<Vec<_>>();
        assert_eq!(
            https_arguments.first().copied(),
            Some(OsStr::new("--disable"))
        );
        let certificate_position = https_arguments
            .iter()
            .position(|argument| *argument == OsStr::new("--cacert"))
            .expect("HTTPS proof command must retain an explicit CA certificate");
        assert_eq!(
            https_arguments.get(certificate_position + 1).copied(),
            Some(certificate.as_os_str())
        );
    }

    #[test]
    fn hostile_curlrc_is_ignored_only_when_disable_is_first() {
        let mut environment =
            HostileCurlEnvironment::create().expect("hostile curl environment must be created");

        let (hermetic_output, hermetic_request) =
            invoke_loopback_curl(&environment, DisableMutation::None)
                .expect("production curl invocation must complete");
        require_output(hermetic_output, "hermetic HTTP", RESPONSE_BODY)
            .expect("production curl invocation must preserve the exact response body");
        assert_request_is_hermetic(&hermetic_request);

        for mutation in [DisableMutation::Remove, DisableMutation::MoveToSecond] {
            let (mutated_output, mutated_request) = invoke_loopback_curl(&environment, mutation)
                .expect("mutated curl invocation must complete");
            assert!(mutated_output.status.success());
            assert_eq!(
                String::from_utf8(mutated_output.stdout.clone())
                    .expect("curl stdout must remain UTF-8"),
                format!("{RESPONSE_BODY}{HOSTILE_CANARY}"),
                "mutation control did not prove that curl loaded hostile startup configuration"
            );
            assert!(
                request_contains_header(&mutated_request, HOSTILE_HEADER),
                "mutation control did not inject the hostile curlrc header"
            );
            assert!(
                require_output(mutated_output, "mutated HTTP", RESPONSE_BODY).is_err(),
                "the strict production output assertion must reject a curlrc canary"
            );
        }
        let temporary_root = environment.root.clone();
        environment
            .cleanup()
            .expect("hostile curl environment must be explicitly removed");
        assert!(!temporary_root.exists());
    }

    fn invoke_loopback_curl(
        environment: &HostileCurlEnvironment,
        mutation: DisableMutation,
    ) -> io::Result<(Output, Vec<u8>)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let proxy = format!("http://{address}");
        let target = "http://127.0.0.1:9/int-002-curlrc-proof";
        let curl = resolve_real_curl()?;
        let command = build_curl_command(&curl, &proxy, target, None);
        let mut command = mutate_disable_position(command, mutation)?;
        environment.apply_to(&mut command);

        let server = spawn_loopback_responder(listener);
        let output_result = command.output();
        let request_result = join_responder(server);
        let output = output_result?;
        let request = request_result?;
        Ok((output, request))
    }

    fn mutate_disable_position(command: Command, mutation: DisableMutation) -> io::Result<Command> {
        if matches!(mutation, DisableMutation::None) {
            return Ok(command);
        }
        let program = command.get_program().to_os_string();
        let original_arguments = command.get_args().map(OsString::from).collect::<Vec<_>>();
        require(
            original_arguments
                .first()
                .is_some_and(|argument| argument == "--disable"),
            "mutation control requires --disable to begin as the first argument",
        )?;
        let mut arguments = original_arguments.clone();
        let disable = arguments.remove(0);
        if matches!(mutation, DisableMutation::MoveToSecond) {
            require(
                !arguments.is_empty(),
                "mutation control requires at least one non-disable argument",
            )?;
            arguments.insert(1, disable);
        }
        let expected_arguments = match mutation {
            DisableMutation::None => unreachable!("the no-mutation case returned above"),
            DisableMutation::Remove => original_arguments[1..].to_vec(),
            DisableMutation::MoveToSecond => {
                let mut expected = original_arguments[1..].to_vec();
                expected.insert(1, original_arguments[0].clone());
                expected
            }
        };
        require(
            arguments == expected_arguments,
            "mutation control changed arguments other than --disable placement",
        )?;
        let mut mutated = Command::new(program);
        mutated.args(arguments);
        Ok(mutated)
    }

    fn resolve_real_curl() -> io::Result<PathBuf> {
        let path = env::var_os("PATH")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "PATH is missing"))?;
        let executable_names: &[&str] = if cfg!(windows) {
            &["curl.exe", "curl"]
        } else {
            &["curl"]
        };
        for directory in env::split_paths(&path) {
            for executable_name in executable_names {
                let candidate = directory.join(executable_name);
                if !candidate.is_file() {
                    continue;
                }
                let Ok(absolute) = fs::canonicalize(candidate) else {
                    continue;
                };
                let Ok(version) = Command::new(&absolute)
                    .args(["--disable", "--version"])
                    .output()
                else {
                    continue;
                };
                if version.status.success() && version.stdout.starts_with(b"curl ") {
                    return Ok(absolute);
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "PATH contains no absolute executable that identifies as curl",
        ))
    }

    fn spawn_loopback_responder(listener: TcpListener) -> JoinHandle<io::Result<Vec<u8>>> {
        thread::spawn(move || respond_once(listener))
    }

    fn join_responder(server: JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
        server
            .join()
            .map_err(|_| io::Error::other("loopback curl responder thread panicked"))?
    }

    fn respond_once(listener: TcpListener) -> io::Result<Vec<u8>> {
        let deadline = Instant::now() + SERVER_DEADLINE;
        listener.set_nonblocking(true)?;
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _peer)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "loopback curl responder accept deadline expired",
                        ));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        };
        let request = read_bounded_request(&mut stream, deadline)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "loopback curl responder write deadline expired",
            ));
        }
        stream.set_write_timeout(Some(remaining))?;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{RESPONSE_BODY}",
            RESPONSE_BODY.len()
        );
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        Ok(request)
    }

    fn read_bounded_request(stream: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            if request.len() >= MAX_REQUEST_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "loopback curl request exceeded the byte limit",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "loopback curl responder read deadline expired",
                ));
            }
            stream.set_read_timeout(Some(remaining.min(Duration::from_millis(250))))?;
            match stream.read(&mut buffer) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "loopback curl request ended before its headers",
                    ));
                }
                Ok(read) => {
                    let available = MAX_REQUEST_BYTES.saturating_sub(request.len());
                    if read > available {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "loopback curl request exceeded the byte limit",
                        ));
                    }
                    request.extend_from_slice(&buffer[..read]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(request)
    }

    fn assert_request_is_hermetic(request: &[u8]) {
        assert!(request_contains_header(request, PROOF_HEADER));
        assert!(!request_contains_header(request, HOSTILE_HEADER));
    }

    fn request_contains_header(request: &[u8], header: &str) -> bool {
        String::from_utf8_lossy(request)
            .lines()
            .any(|line| line.eq_ignore_ascii_case(header))
    }
}
