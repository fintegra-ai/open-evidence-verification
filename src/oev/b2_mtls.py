# SPDX-License-Identifier: Apache-2.0

"""Mutual-TLS channel for Model B2 (round 4, worker D).

Replaces the prototype's in-process byte handoff / stdio pipe with a
real mutually-authenticated TLS channel on localhost:

* a local test CA (generated here, **test-only** — short-lived, CN
  prefixed ``TEST-ONLY``, never a production CA) issues one
  certificate for the witness server (CN ``b2-witness``) and one for
  the producer client (CN ``b2-producer``);
* the server requires a client certificate signed by the test CA
  (``CERT_REQUIRED``) and additionally checks the peer CN allow-list;
* the client requires a server certificate signed by the test CA and
  checks the server CN is ``b2-witness``;
* TLS 1.2 minimum (1.3 negotiated when both sides offer it);
* the JSON-lines request/response protocol is unchanged
  (``b2_worker._handle`` dispatches on the server side), so the
  witness logic is identical — only the transport is authenticated.

Trust boundary, stated honestly: this is still **same-host**
isolation (separate process / venv / keystore / mTLS trust domain),
NOT a separate physical host. mTLS stops a *different local process*
that does not hold a client certificate from impersonating the
producer, and stops a network-level eavesdropper on localhost from
reading the bundle bytes in transit. It does NOT stop a host-level
attacker (root / same-user compromise) — that attacker can read the
keystore and the CA. A production deployment needs the witness on a
separately administered host with its own CA and key custody; see
``docs/B2_DEPLOYMENT_REPORT.md``.
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .b2_witness import B2ReexecutingWitness, validate_witness_authorization

TEST_ONLY_CN_PREFIX = "TEST-ONLY "
B2_WITNESS_SERVER_CN = "b2-witness"
B2_PRODUCER_CLIENT_CN = "b2-producer"
_CA_VALIDITY_DAYS = 7
_CERT_VALIDITY_DAYS = 7


# -- test PKI -------------------------------------------------------------------


def _pem_private_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def create_test_ca(common_name: str = "oev-b2-test-ca") -> tuple[bytes, bytes]:
    """Create a local **test-only** CA (RSA-2048, 7-day validity).

    Returns ``(ca_private_key_pem, ca_cert_pem)``. The subject CN is
    prefixed ``TEST-ONLY`` so the certificate can never be mistaken for
    a production CA. The CA private key must be kept in the witness
    keystore's ``tls/`` directory (0o700) and never distributed.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, TEST_ONLY_CN_PREFIX + common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "oev-b2 test-only PKI"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=_CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return _pem_private_key(key), _pem_cert(cert)


def issue_test_certificate(
    ca_private_key_pem: bytes,
    ca_cert_pem: bytes,
    common_name: str,
    dns_names: tuple[str, ...] = ("localhost",),
) -> tuple[bytes, bytes]:
    """Issue a short-lived leaf certificate from the test CA.

    Returns ``(private_key_pem, cert_pem)``. ``common_name`` must be
    ``b2-witness`` (server) or ``b2-producer`` (client); anything else
    is refused by the peer-CN checks, so a stray certificate cannot
    impersonate either role.
    """
    if common_name not in (B2_WITNESS_SERVER_CN, B2_PRODUCER_CLIENT_CN):
        raise ValueError(
            f"Refusing to issue a B2 test certificate for CN {common_name!r}: "
            "only 'b2-witness' and 'b2-producer' exist in this deployment"
        )
    ca_key = serialization.load_pem_private_key(ca_private_key_pem, password=None)
    if not isinstance(ca_key, rsa.RSAPrivateKey):
        # The test CA is always RSA (see create_test_ca); refuse anything else
        # rather than signing with an unexpected key type.
        raise TypeError("B2 test CA key must be RSA")
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, TEST_ONLY_CN_PREFIX + common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "oev-b2 test-only PKI"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=_CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return _pem_private_key(key), _pem_cert(cert)


def write_test_pki(
    tls_dir: str | Path, *, ca_key: bytes, ca_cert: bytes, cert: bytes, key: bytes, role: str
) -> dict[str, str]:
    """Write test PKI material into a keystore ``tls/`` dir (0o700/0o600).

    Also writes a ``TEST-ONLY.json`` marker so the directory is
    self-describing as test PKI. Returns the file paths (as strings).
    """
    tls_dir = Path(tls_dir)
    tls_dir.mkdir(parents=True, exist_ok=True)
    tls_dir.chmod(0o700)
    files = {
        "ca_cert": ("ca-cert.pem", ca_cert, 0o644),
        "ca_key": ("ca-key.pem", ca_key, 0o600),
        "cert": (f"{role}-cert.pem", cert, 0o644),
        "key": (f"{role}-key.pem", key, 0o600),
    }
    out: dict[str, str] = {}
    for label, (name, data, mode) in files.items():
        path = tls_dir / name
        path.write_bytes(data)
        path.chmod(mode)
        out[label] = str(path)
    marker = tls_dir / "TEST-ONLY.json"
    marker.write_bytes(
        json.dumps(
            {
                "test_only": True,
                "note": "Local test PKI for B2 development only. "
                "Not a production CA; short-lived certificates; "
                "do not distribute the CA key.",
                "role": role,
            },
            indent=2,
        ).encode("utf-8")
    )
    marker.chmod(0o600)
    return out


def _peer_cn(peercert: dict[str, Any]) -> str:
    for rdn in peercert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return str(value)
    return ""


def build_server_ssl_context(
    server_cert_pem: bytes, server_key_pem: bytes, ca_cert_pem: bytes
) -> ssl.SSLContext:
    """TLS server context: requires a CA-signed client certificate."""
    import tempfile

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        cert_file = td_path / "server-cert.pem"
        key_file = td_path / "server-key.pem"
        ca_file = td_path / "ca-cert.pem"
        cert_file.write_bytes(server_cert_pem)
        key_file.write_bytes(server_key_pem)
        ca_file.write_bytes(ca_cert_pem)
        ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        ctx.load_verify_locations(cafile=str(ca_file))
    return ctx


def build_client_ssl_context(
    client_cert_pem: bytes, client_key_pem: bytes, ca_cert_pem: bytes
) -> ssl.SSLContext:
    """TLS client context: requires a CA-signed server certificate."""
    import tempfile

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False  # localhost IP/CN is checked explicitly, see below
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        cert_file = td_path / "client-cert.pem"
        key_file = td_path / "client-key.pem"
        ca_file = td_path / "ca-cert.pem"
        cert_file.write_bytes(client_cert_pem)
        key_file.write_bytes(client_key_pem)
        ca_file.write_bytes(ca_cert_pem)
        ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        ctx.load_verify_locations(cafile=str(ca_file))
    return ctx


def _check_server_cn(peercert: dict[str, Any]) -> None:
    cn = _peer_cn(peercert)
    expected = TEST_ONLY_CN_PREFIX + B2_WITNESS_SERVER_CN
    if cn != expected:
        raise ssl.SSLCertVerificationError(
            f"mTLS server certificate CN is {cn!r}, expected {expected!r}"
        )


# -- witness server --------------------------------------------------------------


class MTLSWitnessServer:
    """TLS server wrapping a :class:`B2ReexecutingWitness`.

    One JSON-lines request per TLS connection (the client opens a fresh
    connection per call, like the stdio worker protocol). The witness
    service object — and its private key — live only in this process.
    """

    def __init__(
        self,
        witness: B2ReexecutingWitness,
        server_cert_pem: bytes,
        server_key_pem: bytes,
        ca_cert_pem: bytes,
        host: str = "127.0.0.1",
        port: int = 0,
        allowed_client_cns: tuple[str, ...] = (B2_PRODUCER_CLIENT_CN,),
    ) -> None:
        self._witness = witness
        self._ctx = build_server_ssl_context(server_cert_pem, server_key_pem, ca_cert_pem)
        self._host = host
        self._port = port
        self._allowed = {TEST_ONLY_CN_PREFIX + cn for cn in allowed_client_cns}
        self._sock: socket.socket | None = None
        self._stop = threading.Event()

    @property
    def port(self) -> int:
        if self._sock is None:
            raise RuntimeError("server is not listening")
        return int(self._sock.getsockname()[1])

    def serve_forever(self, sock: socket.socket | None = None) -> None:
        from .b2_worker import _handle

        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self._host, self._port))
            sock.listen(16)
        sock.settimeout(0.5)
        self._sock = sock
        while not self._stop.is_set():
            try:
                conn, _addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_conn, args=(conn, _handle), daemon=True).start()
        try:
            sock.close()
        except OSError:
            pass

    def _serve_conn(self, conn: socket.socket, handle: Any) -> None:
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError:
            try:
                conn.close()
            except OSError:
                pass
            return
        try:
            peer = tls.getpeercert()
            if peer is None:
                return  # no client certificate: unauthenticated, no service
            if _peer_cn(peer) not in self._allowed:
                return  # unauthenticated client: no service, no error details
            buf = b""
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        request = json.loads(line.decode("utf-8"))
                        if not isinstance(request, dict):
                            raise ValueError("request is not an object")  # noqa: TRY004
                        response = handle(self._witness, request)
                    except ValueError as exc:
                        response = {"ok": False, "error": f"invalid request: {exc}"}
                    except (KeyError, TypeError, OSError) as exc:
                        response = {"ok": False, "error": str(exc)}
                    tls.sendall((json.dumps(response) + "\n").encode("utf-8"))
                    if str(request.get("op")) == "shutdown":
                        return
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass


# -- witness client (spawns the server as a separate process) --------------------


class B2MTLSProcessWitness:
    """Client for a B2 witness served over mTLS by a separate process.

    Spawns ``python -m oev.b2_mtls --serve ...`` under ``python=``
    (point it at the witness venv's interpreter). The witness private
    key file is read by the server process only and never crosses into
    this process; the TLS client certificate authenticates this side.
    ``channel == "mtls-tls13-localhost"`` is recorded in B2 manifests.
    """

    channel = "mtls-tls13-localhost"

    def __init__(
        self,
        private_key_path: str | Path,
        key_id: str,
        log_path: str | Path,
        *,
        client_cert_pem: bytes,
        client_key_pem: bytes,
        ca_cert_pem: bytes,
        server_cert_pem: bytes,
        server_key_pem: bytes,
        log_id: str = "hea-b2-log-001",
        timeout_seconds: float = 120.0,
        checkpoint_key_path: str | Path | None = None,
        checkpoint_key_id: str = "",
        authorization: dict[str, Any] | None = None,
        python: str | Path | None = None,
        host: str = "127.0.0.1",
    ) -> None:
        self._private_key_path = Path(private_key_path)
        self.key_id = key_id
        self._log_path = Path(log_path)
        self._log_id = log_id
        self._timeout = timeout_seconds
        self._checkpoint_key_path = Path(checkpoint_key_path) if checkpoint_key_path else None
        self._checkpoint_key_id = checkpoint_key_id
        self.authorization = (
            validate_witness_authorization(authorization) if authorization is not None else None
        )
        if self.authorization is not None and self.authorization["witness_key_id"] != key_id:
            raise ValueError(
                "Witness authorisation witness_key_id does not match this witness key_id"
            )
        self._python = str(python) if python is not None else sys.executable
        self._host = host
        self._client_ctx = build_client_ssl_context(client_cert_pem, client_key_pem, ca_cert_pem)
        # Server-side TLS material is handed to the spawned server process
        # via temp files (never through this process's memory after spawn).
        self._server_cert_pem = bytes(server_cert_pem)
        self._server_key_pem = bytes(server_key_pem)
        self._ca_cert_pem = bytes(ca_cert_pem)
        self._proc: subprocess.Popen[str] | None = None
        self._port: int | None = None
        self._tmpdir: Any = None

    @property
    def log_path(self) -> Path:
        return self._log_path

    def __enter__(self) -> B2MTLSProcessWitness:  # noqa: PYI034 - returns self at runtime
        import tempfile

        self._tmpdir = tempfile.TemporaryDirectory(prefix="oev-b2-mtls-")
        td = Path(self._tmpdir.name)
        (td / "server-cert.pem").write_bytes(self._server_cert_pem)
        (td / "server-key.pem").write_bytes(self._server_key_pem)
        (td / "ca-cert.pem").write_bytes(self._ca_cert_pem)
        ready_file = td / "ready.json"
        argv = [
            self._python,
            "-m",
            "oev.b2_mtls",
            "--serve",
            "--key",
            str(self._private_key_path),
            "--key-id",
            self.key_id,
            "--log",
            str(self._log_path),
            "--log-id",
            self._log_id,
            "--tls-cert",
            str(td / "server-cert.pem"),
            "--tls-key",
            str(td / "server-key.pem"),
            "--ca-cert",
            str(td / "ca-cert.pem"),
            "--ready-file",
            str(ready_file),
        ]
        if self._checkpoint_key_path is not None:
            argv += [
                "--checkpoint-key",
                str(self._checkpoint_key_path),
                "--checkpoint-key-id",
                self._checkpoint_key_id,
            ]
        self._proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            if ready_file.is_file():
                self._port = int(json.loads(ready_file.read_text())["port"])
                break
            if self._proc.poll() is not None:
                stderr = self._proc.stderr.read() if self._proc.stderr else ""
                raise RuntimeError(f"B2 mTLS witness server exited early: {stderr[-1000:]}")
            time.sleep(0.05)
        if self._port is None:
            raise RuntimeError("B2 mTLS witness server did not become ready in time")
        ready = self._call("ping", {})
        if not ready.get("ok"):
            raise RuntimeError(f"B2 mTLS witness server failed to start: {ready}")
        return self

    def __exit__(self, *exc: object) -> None:
        if self._proc is not None:
            try:
                self._call("shutdown", {})
            except (RuntimeError, TimeoutError, OSError):
                pass
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None

    def _call(self, op: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self._port is None:
            raise RuntimeError("B2 mTLS witness server is not running")
        raw = socket.create_connection((self._host, self._port), timeout=self._timeout)
        try:
            tls = self._client_ctx.wrap_socket(raw, server_hostname="localhost")
            server_cert = tls.getpeercert()
            if server_cert is None:
                raise RuntimeError("B2 mTLS witness presented no server certificate")
            _check_server_cn(server_cert)
            tls.settimeout(self._timeout)
            tls.sendall((json.dumps({"op": op, **payload}) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = tls.recv(65536)
                if not chunk:
                    raise RuntimeError(f"B2 mTLS witness closed the connection during {op!r}")
                buf += chunk
            response = json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
        finally:
            try:
                raw.close()
            except OSError:
                pass
        if not isinstance(response, dict) or not response.get("ok"):
            raise RuntimeError(
                f"B2 mTLS witness error for {op!r}: {response.get('error', response)}"
            )
        return response

    # -- same method surface as B2ProcessWitness ------------------------------
    def receive_bundle(self, package_bytes: bytes, profile_bytes: bytes) -> dict[str, str]:
        result = self._call(
            "receive_bundle",
            {
                "package_b64": base64.b64encode(package_bytes).decode("ascii"),
                "profile_b64": base64.b64encode(profile_bytes).decode("ascii"),
            },
        )
        return {
            "bundle_digest": str(result["bundle_digest"]),
            "profile_digest": str(result["profile_digest"]),
        }

    def code_digest(self) -> str:
        return str(self._call("code_digest", {})["code_digest"])

    def issue_commitment(
        self, partial_prebinding: dict[str, Any], issued_at_claimed: str
    ) -> dict[str, Any]:
        return self._call(
            "commit", {"prebinding": partial_prebinding, "issued_at_claimed": issued_at_claimed}
        )

    def start_execution(
        self, execution_id: str, commitment_digest: str, claimed_time: str
    ) -> dict[str, Any]:
        return self._call(
            "start",
            {
                "execution_id": execution_id,
                "commitment_digest": commitment_digest,
                "claimed_time": claimed_time,
            },
        )

    def check_completed(
        self, execution_id: str, check_id: str, result_digest: str, claimed_time: str
    ) -> dict[str, Any]:
        return self._call(
            "check_completed",
            {
                "execution_id": execution_id,
                "check_id": check_id,
                "result_digest": result_digest,
                "claimed_time": claimed_time,
            },
        )

    def complete_execution(
        self, execution_id: str, status: str, claimed_time: str
    ) -> dict[str, Any]:
        return self._call(
            "complete",
            {"execution_id": execution_id, "status": status, "claimed_time": claimed_time},
        )

    def attest(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._call("attest", {"payload": payload})

    def checkpoint(self, claimed_time: str) -> dict[str, Any]:
        return self._call("checkpoint", {"claimed_time": claimed_time})

    def completeness(self, checkpoint: dict[str, Any], claimed_time: str) -> dict[str, Any]:
        return self._call("completeness", {"checkpoint": checkpoint, "claimed_time": claimed_time})

    def sign_completeness(self, statement: dict[str, Any]) -> dict[str, Any]:
        return self._call("sign_completeness", {"statement": statement})

    def reexecute(
        self,
        package_bytes: bytes,
        profile: Any,
        package_trust_keys: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return self._call(
            "reexecute",
            {
                "package_b64": base64.b64encode(package_bytes).decode("ascii"),
                "profile": profile.to_dict(),
                "package_trust_keys": package_trust_keys or [],
            },
        )

    def compare_results(
        self,
        producer_checks: list[dict[str, Any]],
        witness_checks: list[dict[str, Any]],
    ) -> list[str]:
        witness_by_id = {c["check_id"]: c for c in witness_checks}
        mismatches: list[str] = []
        for claimed in producer_checks:
            check_id = str(claimed["check_id"])
            observed = witness_by_id.get(check_id)
            if observed is None:
                mismatches.append(check_id)
                continue
            if str(claimed.get("status")) != str(observed.get("status")) or str(
                claimed.get("detail", "")
            ) != str(observed.get("detail", "")):
                mismatches.append(check_id)
        return mismatches

    def export_log_jsonl(self) -> bytes:
        result = self._call("export_log", {})
        return base64.b64decode(str(result["log_b64"]).encode("ascii"))


# -- server entry point ----------------------------------------------------------


def _serve_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oev.b2_mtls")
    parser.add_argument("--serve", action="store_true", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--checkpoint-key")
    parser.add_argument("--checkpoint-key-id", default="")
    parser.add_argument("--log", required=True)
    parser.add_argument("--log-id", default="hea-b2-log-001")
    parser.add_argument("--tls-cert", required=True)
    parser.add_argument("--tls-key", required=True)
    parser.add_argument("--ca-cert", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ready-file")
    args = parser.parse_args(argv)
    try:
        private_key_pem = Path(args.key).read_bytes()
        checkpoint_key_pem = Path(args.checkpoint_key).read_bytes() if args.checkpoint_key else None
        witness = B2ReexecutingWitness(
            private_key_pem,
            key_id=args.key_id,
            log_id=args.log_id,
            log_path=args.log,
            checkpoint_private_key_pem=checkpoint_key_pem,
            checkpoint_key_id=args.checkpoint_key_id,
        )
        server = MTLSWitnessServer(
            witness,
            server_cert_pem=Path(args.tls_cert).read_bytes(),
            server_key_pem=Path(args.tls_key).read_bytes(),
            ca_cert_pem=Path(args.ca_cert).read_bytes(),
            host=args.host,
            port=args.port,
        )
    except (ValueError, OSError) as exc:
        sys.stderr.write(f"B2 mTLS witness server failed to start: {exc}\n")
        return 1
    # Bind eagerly so the ready file reports the real port.
    import socket as _socket

    probe = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    probe.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    probe.bind((args.host, args.port))
    probe.listen(16)
    probe.settimeout(0.5)
    port = int(probe.getsockname()[1])
    server._sock = probe
    if args.ready_file:
        Path(args.ready_file).write_text(json.dumps({"port": port, "host": args.host}))
    print(f"READY port={port}", flush=True)
    try:
        server.serve_forever(sock=probe)
    except KeyboardInterrupt:
        return 0
    return 0


def main(argv: list[str] | None = None) -> int:
    return _serve_main(argv)


if __name__ == "__main__":
    sys.exit(main())
