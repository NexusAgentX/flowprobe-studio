#!/usr/bin/env python3
"""Prove real sing-box HTTP and HTTPS CONNECT paths using loopback-only origins."""
from __future__ import annotations

import argparse
import hashlib
import http.server
import os
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "integration" / "v0_1" / "Cargo.toml"
RUST_BINARY = "flowprobe-v0-1-real-singbox-proof"
EXPECTED_VERSION = "sing-box version 1.13.19"
EXPECTED_REVISION = "Revision: b5ebaa1fc0f2b94256180b95468e73ef53caa27d"
PROOF_HEADER = "INT001-LOOPBACK-PROOF"
HTTP_BODY = "INT001_HTTP_ORIGIN_OK"
HTTPS_BODY = "INT001_HTTPS_ORIGIN_OK"
UNSUPPORTED_EXIT = 77


class ProofFailure(RuntimeError):
    pass


class ProofServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, response_body: str) -> None:
        super().__init__(("127.0.0.1", 0), ProofHandler)
        self.response_body = response_body.encode("ascii")
        self.records: list[tuple[str, str | None]] = []
        self.records_lock = threading.Lock()


class ProofHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler callback name
        server = self.server
        if not isinstance(server, ProofServer):
            self.send_error(500)
            return
        with server.records_lock:
            server.records.append((self.path, self.headers.get("X-FlowProbe-Proof")))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(server.response_body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(server.response_body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def fail(message: str) -> NoReturn:
    raise ProofFailure(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def executable_from_env(name: str) -> Path:
    value = os.environ.get(name)
    require(value is not None and value != "", f"required environment variable {name} is missing")
    path = Path(value)
    require(path.is_absolute(), f"{name} must be an absolute path")
    require(path.is_file(), f"{name} is not a regular file: {path}")
    require(os.access(path, os.X_OK), f"{name} is not executable: {path}")
    return path


def required_tool(name: str) -> Path:
    value = shutil.which(name)
    require(value is not None, f"required command is missing from PATH: {name}")
    path = Path(value).resolve()
    require(path.is_absolute() and path.is_file(), f"resolved {name} path is invalid: {path}")
    return path


def run_checked(command: list[str], label: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        fail(f"{label} timed out")
    except OSError as exc:
        fail(f"cannot run {label}: {exc}")
    if result.returncode != 0:
        diagnostic = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        fail(f"{label} failed with exit code {result.returncode}: {diagnostic}")
    return result


def binary_evidence(binary: Path) -> str:
    version = run_checked([str(binary), "version"], "sing-box version", timeout=10)
    lines = [line.strip() for line in version.stdout.splitlines() if line.strip()]
    require(lines and lines[0] == EXPECTED_VERSION, f"unexpected sing-box version: {lines[:1]!r}")
    revisions = [line for line in lines if line.startswith("Revision:")]
    require(revisions == [EXPECTED_REVISION], f"unexpected sing-box revision: {revisions!r}")

    digest = hashlib.sha256()
    with binary.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    checksum = digest.hexdigest()
    print(f"sing-box-binary={binary}", flush=True)
    print(f"sing-box-version={EXPECTED_VERSION.removeprefix('sing-box version ')}", flush=True)
    print(f"sing-box-revision={EXPECTED_REVISION.removeprefix('Revision: ')}", flush=True)
    print(f"sing-box-sha256={checksum}", flush=True)
    return checksum


def generate_certificate(openssl: Path, directory: Path) -> tuple[Path, Path]:
    config = directory / "openssl.cnf"
    certificate = directory / "origin.crt"
    private_key = directory / "origin.key"
    config.write_text(
        """[req]
distinguished_name = distinguished_name
x509_extensions = proof_extensions
prompt = no

[distinguished_name]
CN = 127.0.0.1

[proof_extensions]
subjectAltName = IP:127.0.0.1
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign
extendedKeyUsage = serverAuth
""",
        encoding="utf-8",
    )
    run_checked(
        [
            str(openssl),
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-config",
            str(config),
            "-extensions",
            "proof_extensions",
        ],
        "ephemeral self-signed certificate generation",
    )
    os.chmod(private_key, 0o600)
    require(
        stat.S_IMODE(private_key.stat().st_mode) == 0o600,
        "ephemeral TLS private key mode is not 0600",
    )
    return certificate, private_key


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def process_group_is_alive(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        fail(f"cannot inspect managed runtime process group {process_group}")
    return True


def force_runtime_cleanup(pid_file: Path) -> None:
    if not pid_file.exists():
        return
    try:
        process_group = int(pid_file.read_text(encoding="ascii").strip())
    except (OSError, UnicodeError, ValueError) as exc:
        fail(f"cannot read the managed runtime cleanup identity: {exc}")
    require(process_group > 1, "managed runtime cleanup identity is unsafe")
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        return
    except PermissionError:
        fail(f"cannot terminate managed runtime process group {process_group}")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and process_group_is_alive(process_group):
        time.sleep(0.05)
    if process_group_is_alive(process_group):
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            fail(f"cannot kill managed runtime process group {process_group}")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and process_group_is_alive(process_group):
        time.sleep(0.05)
    require(
        not process_group_is_alive(process_group),
        f"managed runtime process group {process_group} survived forced cleanup",
    )
    pid_file.unlink(missing_ok=True)


def run_rust_proof(environment: dict[str, str], pid_file: Path) -> None:
    command = [
        "cargo",
        "run",
        "--manifest-path",
        str(MANIFEST),
        "--locked",
        "--bin",
        RUST_BINARY,
    ]
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            start_new_session=True,
        )
    except OSError as exc:
        fail(f"cannot start the Rust local-network proof: {exc}")
    try:
        return_code = process.wait(timeout=300)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        force_runtime_cleanup(pid_file)
        fail("Rust local-network proof timed out; its isolated process group was terminated")
    if return_code != 0:
        force_runtime_cleanup(pid_file)
        fail(f"Rust local-network proof failed with exit code {return_code}")


def records(server: ProofServer) -> list[tuple[str, str | None]]:
    with server.records_lock:
        return list(server.records)


def prove() -> None:
    binary = executable_from_env("FLOWPROBE_SING_BOX_BIN")
    curl = required_tool("curl")
    openssl = required_tool("openssl")
    binary_evidence(binary)
    require(MANIFEST.is_file(), f"isolated integration manifest is missing: {MANIFEST}")

    with tempfile.TemporaryDirectory(prefix="flowprobe-v0-1-local-") as temporary:
        directory = Path(temporary)
        state_directory = directory / "state"
        state_directory.mkdir(mode=0o700)
        certificate, _private_key = generate_certificate(openssl, directory)

        servers: list[ProofServer] = []
        threads: list[threading.Thread] = []
        started: list[tuple[ProofServer, threading.Thread]] = []
        try:
            http_origin = ProofServer(HTTP_BODY)
            servers.append(http_origin)
            https_origin = ProofServer(HTTPS_BODY)
            servers.append(https_origin)
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(certfile=certificate, keyfile=directory / "origin.key")
            https_origin.socket = tls_context.wrap_socket(https_origin.socket, server_side=True)
            threads = [
                threading.Thread(target=server.serve_forever, daemon=True, name=f"origin-{index}")
                for index, server in enumerate(servers)
            ]
            for server, thread in zip(servers, threads, strict=True):
                thread.start()
                started.append((server, thread))

            proxy_port = reserve_loopback_port()
            http_port = int(http_origin.server_address[1])
            https_port = int(https_origin.server_address[1])
            http_url = f"http://127.0.0.1:{http_port}/http-proof"
            https_url = f"https://127.0.0.1:{https_port}/https-proof"
            environment = os.environ.copy()
            pid_file = state_directory / "runtime.pid"
            environment.update(
                {
                    "FLOWPROBE_SING_BOX_BIN": str(binary),
                    "FLOWPROBE_CURL_BIN": str(curl),
                    "FLOWPROBE_V0_1_STATE_DIR": str(state_directory),
                    "FLOWPROBE_V0_1_RUNTIME_PID_FILE": str(pid_file),
                    "FLOWPROBE_V0_1_TLS_CERT": str(certificate),
                    "FLOWPROBE_V0_1_PROXY_PORT": str(proxy_port),
                    "FLOWPROBE_V0_1_HTTP_URL": http_url,
                    "FLOWPROBE_V0_1_HTTPS_URL": https_url,
                    "FLOWPROBE_V0_1_HTTP_EXPECTED": HTTP_BODY,
                    "FLOWPROBE_V0_1_HTTPS_EXPECTED": HTTPS_BODY,
                }
            )
            run_rust_proof(environment, pid_file)
            require(
                records(http_origin) == [("/http-proof", PROOF_HEADER)],
                f"HTTP origin did not receive exactly one authenticated proof request: {records(http_origin)!r}",
            )
            require(
                records(https_origin) == [("/https-proof", PROOF_HEADER)],
                f"HTTPS origin did not receive exactly one authenticated proof request: {records(https_origin)!r}",
            )
            managed = [
                path.name
                for path in state_directory.iterdir()
                if path.name.startswith(".flowprobe-runtime-")
            ]
            require(not managed, f"managed runtime configuration remained after stop: {managed!r}")
        finally:
            for server, _thread in started:
                server.shutdown()
            for server in servers:
                server.server_close()
            for _server, thread in started:
                thread.join(timeout=5)
            require(
                all(not thread.is_alive() for _server, thread in started),
                "a loopback origin thread did not stop during cleanup",
            )

    print("http-origin-observed=1")
    print("https-connect-origin-observed=1")
    print("ephemeral-key-mode=0600")
    print("temporary-state-cleanup=passed")
    print("v0.1-real-local-network-proof=passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-supported",
        action="store_true",
        help="turn an unsupported operating system into a failing exit instead of exit 77",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    supported = sys.platform == "darwin" or sys.platform.startswith("linux")
    if not supported:
        message = (
            f"unsupported host OS {sys.platform!r}: this proof requires POSIX process-group "
            "cleanup plus curl and OpenSSL"
        )
        print(f"ERROR: {message}", file=sys.stderr)
        return 1 if args.require_supported else UNSUPPORTED_EXIT
    try:
        prove()
    except ProofFailure as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"ERROR: local-network proof system failure: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
