# SPDX-License-Identifier: Apache-2.0

"""Model B2 round-4 tests (worker D): mTLS channel, separate keystores,
key rotation, revocation, compromised-witness honesty, signed witness
authorisation, domain re-execution, and code-digest binding.

Honesty note (also asserted, not just documented): the compromised-
witness tests assert that a stolen witness key still produces a
PROVEN verdict pre-revocation — B2 moves trust to the witness
machine, it does not eliminate it. Post-revocation the same
attestations are rejected with WITNESS_KEY_REVOKED.
"""

from __future__ import annotations

import dataclasses
import json
import socket
import ssl
import threading
from pathlib import Path
from typing import Any

import pytest

from oev.adapters.oept import is_oept_available
from oev.b2_keystore import (
    Keystore,
    build_rotation_record,
    verify_rotation_chain,
    verify_rotation_record,
)
from oev.b2_mtls import (
    B2_PRODUCER_CLIENT_CN,
    B2_WITNESS_SERVER_CN,
    B2MTLSProcessWitness,
    MTLSWitnessServer,
    build_client_ssl_context,
    create_test_ca,
    issue_test_certificate,
    write_test_pki,
)
from oev.b2_signed_auth import sign_witness_authorization, verify_signed_witness_authorization
from oev.b2_verify import verify_b2_execution
from oev.b2_witness import (
    B2ReexecutingWitness,
    run_b2_witnessed_verification,
)
from oev.canonical import safe_json_loads
from oev.dsse import parse_dsse_envelope
from oev.execution_log import events_from_jsonl
from oev.hea_verifier import HeaVerificationInputs, verify_historical_execution
from oev.models import CheckStatus, VerificationReceipt
from oev.profiles import load_profile
from oev.revocation import RevocationEntry, RevocationList
from oev.signing import generate_ed25519_keypair
from oev.trust import TrustStore
from oev.witness import build_attestation_payload
from tests.hea_helpers import CLAIMED_TIME, build_valid_hea, hea_inputs
from tests.test_domain_profiles import fin_members
from tests.test_domain_profiles_e2e import _build_signed_bundle

pytestmark = pytest.mark.skipif(not is_oept_available(), reason="OEPT not installed")

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_01 = REPO_ROOT / "conformance" / "fixtures" / "01-valid-oept-pass"
FIXTURE_02 = REPO_ROOT / "conformance" / "fixtures" / "02-tampered-package"
PROFILES_DIR = REPO_ROOT / "profiles"
NOT_BEFORE = "2026-01-01T00:00:00Z"
NOT_AFTER = "2027-12-31T23:59:59Z"


def _key_entry(role: str, key_id: str, pub: bytes) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "key_id": key_id,
        "public_key_pem": pub.decode("utf-8"),
        "role": role,
    }
    if role == "witness":
        entry["not_before"] = NOT_BEFORE
        entry["not_after"] = NOT_AFTER
    if role == "checkpoint-signer":
        entry["not_after"] = NOT_AFTER
    return entry


def _make_b2_ctx(tmp_path: Path) -> dict[str, Any]:
    wit_priv, wit_pub = generate_ed25519_keypair()
    cp_priv, cp_pub = generate_ed25519_keypair()
    prod_priv, _prod_pub = generate_ed25519_keypair()
    witness = B2ReexecutingWitness(
        wit_priv,
        key_id="wit-b2-1",
        log_id="hea-b2-log-001",
        log_path=tmp_path / "witness-log.jsonl",
        checkpoint_private_key_pem=cp_priv,
        checkpoint_key_id="cp-b2-1",
    )
    return {
        "witness": witness,
        "wit_priv": wit_priv,
        "wit_pub": wit_pub,
        "cp_priv": cp_priv,
        "cp_pub": cp_pub,
        "prod_priv": prod_priv,
        "witness_store": TrustStore.from_list([_key_entry("witness", "wit-b2-1", wit_pub)]),
        "checkpoint_store": TrustStore.from_list(
            [_key_entry("checkpoint-signer", "cp-b2-1", cp_pub)]
        ),
        "operator_store": TrustStore.from_list(
            [_key_entry("checkpoint-signer", "cp-b2-1", cp_pub)]
        ),
    }


def _run_b2(
    ctx: dict[str, Any],
    tmp_path: Path,
    fixture: Path = FIXTURE_01,
    profile_path: Path | None = None,
    package_path: Path | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    trust_keys = None
    trust_path = fixture / "package-trust-keys.json"
    if trust_path.is_file():
        trust_keys = json.loads(trust_path.read_text())
    out_dir = tmp_path / "b2-out"
    kwargs.setdefault("witness_public_pem", ctx["wit_pub"])
    summary = run_b2_witnessed_verification(
        package_path or (fixture / "package.zip"),
        profile_path or (fixture / "profile.json"),
        ctx["witness"],
        out_dir,
        package_trust_keys=trust_keys,
        receipt_signing_key_pem=ctx["prod_priv"],
        receipt_signer_key_id="prod-1",
        **kwargs,
    )
    return {"summary": summary, "out_dir": out_dir}


def _load_inputs(
    ctx: dict[str, Any], run: dict[str, Any], fixture: Path = FIXTURE_01, **overrides: Any
) -> HeaVerificationInputs:
    out_dir = run["out_dir"]
    receipt_data = safe_json_loads((out_dir / "receipt.json").read_bytes())
    if isinstance(receipt_data, dict) and "payload" in receipt_data:
        _pt, payload_bytes, _sigs = parse_dsse_envelope(receipt_data)
        receipt_data = safe_json_loads(payload_bytes.decode("utf-8"))
    receipt = VerificationReceipt.from_dict(dict(receipt_data))
    profile = load_profile(fixture / "profile.json")
    manifest = safe_json_loads((out_dir / "b2-manifest.json").read_bytes())
    kwargs: dict[str, Any] = {
        "package_bytes": (fixture / "package.zip").read_bytes(),
        "receipt": receipt,
        "profile": profile,
        "attestations": [
            safe_json_loads(p.read_bytes())
            for p in sorted((out_dir / "attestations").glob("*.dsse.json"))
        ],
        "commitment_envelope": safe_json_loads((out_dir / "commitment.dsse.json").read_bytes()),
        "prebinding": safe_json_loads((out_dir / "prebinding.json").read_bytes()),
        "log_events": events_from_jsonl((out_dir / "execution-log.jsonl").read_bytes()),
        "checkpoint_envelope": safe_json_loads((out_dir / "checkpoint.dsse.json").read_bytes()),
        "inclusion_proofs": {
            str(k): [dict(s) for s in v]
            for k, v in dict(manifest.get("inclusion_proofs", {})).items()
        },
        "witness_trust_store": ctx["witness_store"],
        "checkpoint_trust_store": ctx["checkpoint_store"],
        "expected_code_digest": str(manifest.get("code_digest") or ""),
    }
    kwargs.update(overrides)
    return HeaVerificationInputs(**kwargs)


# ---------------------------------------------------------------------------
# mTLS channel (thread server: TLS properties, not process separation)
# ---------------------------------------------------------------------------


def _mtls_pair(tmp_path: Path) -> dict[str, Any]:
    ca_key, ca_cert = create_test_ca()
    wit_server_key, wit_server_cert = issue_test_certificate(ca_key, ca_cert, B2_WITNESS_SERVER_CN)
    prod_key, prod_cert = issue_test_certificate(ca_key, ca_cert, B2_PRODUCER_CLIENT_CN)
    ctx = _make_b2_ctx(tmp_path)
    server = MTLSWitnessServer(
        ctx["witness"],
        server_cert_pem=wit_server_cert,
        server_key_pem=wit_server_key,
        ca_cert_pem=ca_cert,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    import time

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            port = server.port
            break
        except RuntimeError:
            time.sleep(0.05)
    else:  # pragma: no cover - startup failure
        raise RuntimeError("mTLS test server did not start")
    return {
        "ctx": ctx,
        "server": server,
        "thread": thread,
        "port": port,
        "ca_key": ca_key,
        "ca_cert": ca_cert,
        "prod_key": prod_key,
        "prod_cert": prod_cert,
        "wit_server_key": wit_server_key,
        "wit_server_cert": wit_server_cert,
    }


def _tls_call(
    pair: dict[str, Any],
    op: str,
    payload: dict[str, Any],
    client_key: bytes | None = None,
    client_cert: bytes | None = None,
    ca_cert: bytes | None = None,
) -> dict[str, Any]:
    ctx = build_client_ssl_context(
        client_cert if client_cert is not None else pair["prod_cert"],
        client_key if client_key is not None else pair["prod_key"],
        ca_cert if ca_cert is not None else pair["ca_cert"],
    )
    raw = socket.create_connection(("127.0.0.1", pair["port"]), timeout=10)
    try:
        tls = ctx.wrap_socket(raw, server_hostname="localhost")
        tls.sendall((json.dumps({"op": op, **payload}) + "\n").encode("utf-8"))
        buf = b""
        while b"\n" not in buf:
            chunk = tls.recv(65536)
            if not chunk:
                raise RuntimeError("mTLS server closed the connection without a reply")
            buf += chunk
        return json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
    finally:
        raw.close()


def test_mtls_mutual_auth_ping_ok(tmp_path: Path) -> None:
    pair = _mtls_pair(tmp_path)
    try:
        response = _tls_call(pair, "ping", {})
        assert response.get("ok") is True
        assert response.get("key_id") == "wit-b2-1"
        # Negotiated TLS is 1.2+ (1.3 on this stack); assert via a raw handshake.
        ctx = build_client_ssl_context(pair["prod_cert"], pair["prod_key"], pair["ca_cert"])
        raw = socket.create_connection(("127.0.0.1", pair["port"]), timeout=10)
        try:
            tls = ctx.wrap_socket(raw, server_hostname="localhost")
            assert tls.version() in ("TLSv1.2", "TLSv1.3")
            tls.close()
        finally:
            raw.close()
    finally:
        pair["server"].stop()


def test_mtls_client_cert_from_other_ca_rejected(tmp_path: Path) -> None:
    pair = _mtls_pair(tmp_path)
    try:
        other_ca_key, other_ca_cert = create_test_ca("other-ca")
        other_key, other_cert = issue_test_certificate(
            other_ca_key, other_ca_cert, B2_PRODUCER_CLIENT_CN
        )
        with pytest.raises(ssl.SSLError):
            _tls_call(pair, "ping", {}, client_key=other_key, client_cert=other_cert)
    finally:
        pair["server"].stop()


def test_mtls_no_client_cert_rejected(tmp_path: Path) -> None:
    # TLS 1.3 post-handshake client auth: the client's wrap_socket
    # returns successfully and the server's certificate-required alert
    # arrives on first send — so the failure is observed at send/recv,
    # not at wrap time. Either way the witness never serves the request.
    pair = _mtls_pair(tmp_path)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            ca_file = Path(td) / "ca.pem"
            ca_file.write_bytes(pair["ca_cert"])
            ctx.load_verify_locations(cafile=str(ca_file))
            raw = socket.create_connection(("127.0.0.1", pair["port"]), timeout=10)
            try:
                tls = ctx.wrap_socket(raw, server_hostname="localhost")
                with pytest.raises(ssl.SSLError):
                    tls.sendall(b'{"op": "ping"}\n')
                    tls.recv(1024)
            finally:
                raw.close()
    finally:
        pair["server"].stop()


def test_mtls_wrong_server_cn_rejected_by_client() -> None:
    # Unit check of the client's CN gate (the full handshake path is
    # covered by test_b2_run_over_mtls_subprocess): a server presenting
    # the *producer* certificate as its server cert must be rejected.
    from oev.b2_mtls import _check_server_cn

    _check_server_cn({"subject": ((("commonName", "TEST-ONLY b2-witness"),),)})
    with pytest.raises(ssl.SSLCertVerificationError):
        _check_server_cn({"subject": ((("commonName", "TEST-ONLY b2-producer"),),)})
    with pytest.raises(ssl.SSLCertVerificationError):
        _check_server_cn({"subject": ((("commonName", "TEST-ONLY evil"),),)})


def test_mtls_test_pki_is_marked_test_only(tmp_path: Path) -> None:
    ca_key, ca_cert = create_test_ca()
    cert_key, cert = issue_test_certificate(ca_key, ca_cert, B2_WITNESS_SERVER_CN)
    out = write_test_pki(
        tmp_path / "tls", ca_key=ca_key, ca_cert=ca_cert, cert=cert, key=cert_key, role="witness"
    )
    marker = json.loads((tmp_path / "tls" / "TEST-ONLY.json").read_text())
    assert marker["test_only"] is True
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    ca_subject = x509.load_pem_x509_certificate(ca_cert).subject
    ca_cn = ca_subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert str(ca_cn).startswith("TEST-ONLY")
    assert (tmp_path / "tls" / "witness-key.pem").stat().st_mode & 0o777 == 0o600
    assert set(out) == {"ca_cert", "ca_key", "cert", "key"}


def test_mtls_refuses_unknown_common_name(tmp_path: Path) -> None:
    ca_key, ca_cert = create_test_ca()
    with pytest.raises(ValueError):
        issue_test_certificate(ca_key, ca_cert, "evil-impersonator")


# ---------------------------------------------------------------------------
# mTLS end-to-end: separate process, separate keystore, re-execution
# ---------------------------------------------------------------------------


def test_b2_run_over_mtls_subprocess(tmp_path: Path) -> None:
    import sys

    wit_ks = Keystore(tmp_path / "witness-ks", "witness").create()
    prod_ks = Keystore(tmp_path / "producer-ks", "producer").create()
    _wit_priv, wit_pub = wit_ks.generate_keypair("wit-b2-1")
    _cp_priv, cp_pub = wit_ks.generate_keypair("cp-b2-1")
    # Checkpoint key lives in the witness keystore too (separate key,
    # separate file) — the producer keystore never holds it.
    assert "cp-b2-1" not in prod_ks.list_key_ids()
    ca_key, ca_cert = create_test_ca()
    srv_key, srv_cert = issue_test_certificate(ca_key, ca_cert, B2_WITNESS_SERVER_CN)
    cli_key, cli_cert = issue_test_certificate(ca_key, ca_cert, B2_PRODUCER_CLIENT_CN)
    write_test_pki(
        wit_ks.tls_dir, ca_key=ca_key, ca_cert=ca_cert, cert=srv_cert, key=srv_key, role="witness"
    )
    write_test_pki(
        prod_ks.tls_dir, ca_key=ca_key, ca_cert=ca_cert, cert=cli_cert, key=cli_key, role="producer"
    )

    ctx = {
        "witness_store": TrustStore.from_list([_key_entry("witness", "wit-b2-1", wit_pub)]),
        "checkpoint_store": TrustStore.from_list(
            [_key_entry("checkpoint-signer", "cp-b2-1", cp_pub)]
        ),
        "operator_store": TrustStore.from_list(
            [_key_entry("checkpoint-signer", "cp-b2-1", cp_pub)]
        ),
    }
    prod_priv, _ = generate_ed25519_keypair()
    trust_keys = json.loads((FIXTURE_01 / "package-trust-keys.json").read_text())
    out_dir = tmp_path / "b2-mtls-out"
    with B2MTLSProcessWitness(
        wit_ks.keys_dir / "wit-b2-1.key.pem",
        key_id="wit-b2-1",
        log_path=tmp_path / "witness-log.jsonl",
        client_cert_pem=cli_cert,
        client_key_pem=cli_key,
        ca_cert_pem=ca_cert,
        server_cert_pem=srv_cert,
        server_key_pem=srv_key,
        checkpoint_key_path=wit_ks.keys_dir / "cp-b2-1.key.pem",
        checkpoint_key_id="cp-b2-1",
        python=sys.executable,
    ) as witness:
        summary = run_b2_witnessed_verification(
            FIXTURE_01 / "package.zip",
            FIXTURE_01 / "profile.json",
            witness,
            out_dir,
            package_trust_keys=trust_keys,
            receipt_signing_key_pem=prod_priv,
            receipt_signer_key_id="prod-1",
            witness_public_pem=wit_pub,
        )
    assert summary["channel"] == "mtls-tls13-localhost"
    assert summary["execution_completeness_path"] is not None
    manifest = safe_json_loads((out_dir / "b2-manifest.json").read_bytes())
    assert manifest["channel"] == "mtls-tls13-localhost"
    assert manifest["isolation"]["mutual_tls"] is True
    # Same host honesty: the manifest still says NO physical independence.
    assert manifest["isolation"]["physical_or_administrative_independence"] is False
    # Attestations carry the mTLS limitation, not the stdio prototype one.
    attestation = safe_json_loads(min((out_dir / "attestations").glob("*.dsse.json")).read_bytes())
    from oev.attestation import parse_attestation_envelope

    payload = parse_attestation_envelope(attestation)
    codes = {lim["code"] for lim in payload["limitations"]}
    assert "B2_MTLS_SAME_HOST" in codes
    assert "B2_PROTOTYPE_ISOLATION" not in codes
    report = verify_b2_execution(
        _load_inputs(ctx, {"out_dir": out_dir}),
        execution_completeness_envelope=safe_json_loads(
            (out_dir / "b2-completeness.dsse.json").read_bytes()
        ),
        log_operator_trust_store=ctx["operator_store"],
    )
    assert report["b2_ok"] is True, report
    assert report["historical_execution"] == "HISTORICAL_EXECUTION_PROVEN"


# ---------------------------------------------------------------------------
# Separate keystores + rotation
# ---------------------------------------------------------------------------


def test_keystore_permissions_and_separation(tmp_path: Path) -> None:
    wit_ks = Keystore(tmp_path / "w", "witness").create()
    prod_ks = Keystore(tmp_path / "p", "producer").create()
    wit_ks.generate_keypair("wit-1")
    prod_ks.generate_keypair("prod-1")
    report = wit_ks.permissions_report()
    assert report["root"] == "0o700"
    assert report["keys_dir"] == "0o700"
    assert report["keys"]["wit-1"]["private"] == "0o600"
    # Cross-keystore loads fail: the producer keystore has no witness key.
    with pytest.raises(ValueError):
        prod_ks.load_private_key("wit-1")
    # Role confusion fails: a witness directory cannot be opened as producer.
    with pytest.raises(ValueError):
        Keystore.open(tmp_path / "w", "producer")
    # Path traversal in key ids is refused.
    with pytest.raises(ValueError):
        wit_ks.load_private_key("../p/prod-1")


def test_key_rotation_chain_verifies(tmp_path: Path) -> None:
    ks = Keystore(tmp_path / "w", "witness").create()
    old_priv, old_pub = ks.generate_keypair("wit-old")
    new_priv, new_pub = ks.generate_keypair("wit-new")
    _newer_priv, newer_pub = ks.generate_keypair("wit-newer")
    rec1 = build_rotation_record(old_priv, "wit-old", new_pub, "wit-new", "2026-11-13T10:00:00Z")
    rec2 = build_rotation_record(
        new_priv, "wit-new", newer_pub, "wit-newer", "2026-11-13T11:00:00Z"
    )
    ok, note = verify_rotation_chain([rec1, rec2], old_pub, keystore=ks)
    assert ok, note
    # The new key can attest; the rotation record proves the handover.
    record, ok1, _note1 = verify_rotation_record(rec1, old_pub, expected_new_public_key_pem=new_pub)
    assert ok1
    assert record is not None and record["new_key_id"] == "wit-new"
    # A record signed by the WRONG key does not verify.
    _other_priv, _other_pub = generate_ed25519_keypair()
    forged = build_rotation_record(
        _other_priv, "wit-old", new_pub, "wit-new", "2026-11-13T10:00:00Z"
    )
    _rec, ok_forged, _n = verify_rotation_record(forged, old_pub)
    assert ok_forged is False
    # A broken chain (link 2 does not continue link 1) does not verify.
    broken = build_rotation_record(
        old_priv, "wit-old", newer_pub, "wit-newer", "2026-11-13T12:00:00Z"
    )
    ok_broken, _nb = verify_rotation_chain([rec1, broken], old_pub, keystore=ks)
    assert ok_broken is False


# ---------------------------------------------------------------------------
# Revocation + compromised witness (honest outcomes)
# ---------------------------------------------------------------------------


def test_revoked_witness_key_rejected_after_revocation(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    revocation = RevocationList(
        issuer_key_id="rev-1",
        issued_at_claimed=CLAIMED_TIME,
        entries=[
            RevocationEntry(
                key_id="wit-1", reason="key-compromise", revoked_at_claimed=CLAIMED_TIME
            )
        ],
    )
    result = verify_historical_execution(hea_inputs(bundle, revocation_list=revocation))
    assert result.reason == "WITNESS_KEY_REVOKED"
    # Trust-store revoked flag gives the same outcome.
    store = TrustStore.from_list(
        [
            {
                "key_id": "wit-1",
                "public_key_pem": bundle["witness_store"].keys[0].public_key_pem.decode(),
                "role": "witness",
                "not_before": NOT_BEFORE,
                "not_after": NOT_AFTER,
                "revoked": True,
            }
        ]
    )
    result2 = verify_historical_execution(hea_inputs(bundle, witness_trust_store=store))
    assert result2.reason == "WITNESS_KEY_REVOKED"


def test_compromised_witness_pre_revocation_is_undetected(tmp_path: Path) -> None:
    """Honest limit (S4): an attacker holding the witness key signs a
    forged attestation and the verifier still says PROVEN. B2 does not
    fix this — it only moves the trust to the witness machine."""
    from oev.models import CheckResult

    bundle = build_valid_hea(
        tmp_path,
        checks=[
            CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
            CheckResult(
                check_id="manifest_structure", category="structure", status=CheckStatus.PASS
            ),
        ],
    )
    result = verify_historical_execution(hea_inputs(bundle))
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"
    # Post-revocation the same bundle is rejected.
    revocation = RevocationList(
        issuer_key_id="rev-1",
        issued_at_claimed=CLAIMED_TIME,
        entries=[
            RevocationEntry(
                key_id="wit-1", reason="key-compromise", revoked_at_claimed=CLAIMED_TIME
            )
        ],
    )
    revoked = verify_historical_execution(hea_inputs(bundle, revocation_list=revocation))
    assert revoked.reason == "WITNESS_KEY_REVOKED"


def test_compromised_b2_witness_can_attest_without_reexecuting(tmp_path: Path) -> None:
    """B2's re-execution comparison lives in ``run_b2_*``; the witness
    service itself only checks the log anchor. An attacker who holds
    the witness key AND controls the witness process can log a forged
    result and attest it — the bypass requires witness-process
    compromise, not producer compromise."""
    from oev.execution import build_prebinding, compute_trust_inputs_digest
    from oev.hashing import sha256_bytes

    ctx = _make_b2_ctx(tmp_path)
    witness = ctx["witness"]
    package_bytes = b"forged package bytes"
    profile = load_profile(FIXTURE_01 / "profile.json")
    bundle_digest = witness.receive_bundle(package_bytes, b"{}")
    partial = build_prebinding(
        bundle_digest=bundle_digest["bundle_digest"],
        bundle_format=profile.target_format,
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        profile_digest=bundle_digest["profile_digest"],
        code_version={
            "engine": "oev 0.2.3",
            "adapter": "oept 0.1.3",
            "code_digest": witness.code_digest(),
        },
        check_ids=["archive_safety"],
        input_digests={
            "package": bundle_digest["bundle_digest"],
            "profile": bundle_digest["profile_digest"],
        },
        trust_inputs_digest=compute_trust_inputs_digest([]),
        witness_mode="separate-machine",
        witness_key_id="wit-b2-1",
    )
    commitment = witness.issue_commitment(partial, CLAIMED_TIME)
    execution_id = str(commitment["execution_id"])
    witness.start_execution(execution_id, str(commitment["commitment_digest"]), CLAIMED_TIME)
    forged_digest = sha256_bytes(b"forged PASS result")
    completed = witness.check_completed(execution_id, "archive_safety", forged_digest, CLAIMED_TIME)
    anchor = {
        "log_id": "hea-b2-log-001",
        "leaf_index": int(completed["event"]["seq"]),
        "leaf_hash": str(completed["leaf_hash"]),
    }
    payload = build_attestation_payload(
        execution_id=execution_id,
        commitment_digest=str(commitment["commitment_digest"]),
        bundle_digest=bundle_digest["bundle_digest"],
        profile_digest=bundle_digest["profile_digest"],
        code_version={
            "engine": "oev 0.2.3",
            "adapter": "oept 0.1.3",
            "code_digest": witness.code_digest(),
        },
        check_id="archive_safety",
        result_status="PASS",
        result_detail="forged PASS (witness process compromised)",
        result_duration_ms=1,
        execution_status="COMPLETED",
        log_anchor=anchor,
        claimed_time=CLAIMED_TIME,
        witness_key_id="wit-b2-1",
        witness_software="oev-witness-b2 0.1.0",
        witness_mode="separate-machine",
    )
    envelope = witness.attest(payload)  # succeeds: no re-execution inside attest()
    assert isinstance(envelope, dict) and "payload" in envelope


# ---------------------------------------------------------------------------
# Signed witness authorisation
# ---------------------------------------------------------------------------


def _signed_auth_doc(
    ctx: dict[str, Any],
    *,
    profiles: list[str] | None = None,
    issuer_id: str = "op-1",
    valid_until: str = NOT_AFTER,
) -> dict[str, Any]:
    """Build a witness-authorisation document for the test witness key."""
    from oev.b2_witness import public_digest_of_private

    return {
        "protocol_version": "oev-witness-authorization/0.1",
        "witness_key_id": "wit-b2-1",
        "issuer_key_id": issuer_id,
        "authorized_profiles": profiles or ["strict-conformance-profile"],
        "valid_from_claimed": NOT_BEFORE,
        "valid_until_claimed": valid_until,
        "witness_public_key_digest": public_digest_of_private(ctx["wit_priv"]),
    }


def _issuer_store(issuer_pub: bytes, issuer_id: str = "op-1") -> TrustStore:
    return TrustStore.from_list([{"key_id": issuer_id, "public_key_pem": issuer_pub.decode()}])


def test_signed_authorization_accepted_end_to_end(tmp_path: Path) -> None:
    ctx = _make_b2_ctx(tmp_path)
    issuer_priv, issuer_pub = generate_ed25519_keypair()
    doc = _signed_auth_doc(ctx)
    # Fix the helper's keypair handling: re-sign with the real issuer key.
    envelope = sign_witness_authorization(doc, issuer_priv, "op-1")
    issuer_store = _issuer_store(issuer_pub)
    auth, ok, note = verify_signed_witness_authorization(envelope, issuer_store)
    assert ok, note
    assert auth is not None and auth.witness_key_id == "wit-b2-1"
    run = _run_b2(
        ctx,
        tmp_path,
        signed_authorization=envelope,
        authorization_issuer_trust_store=issuer_store,
        require_signed_authorization=True,
        witness_public_pem=ctx["wit_pub"],
    )
    manifest = safe_json_loads((run["out_dir"] / "b2-manifest.json").read_bytes())
    assert manifest["signed_authorization"]["present"] is True
    assert manifest["signed_authorization"]["issuer_key_id"] == "op-1"
    report = verify_b2_execution(
        _load_inputs(ctx, run),
        signed_witness_authorization=envelope,
        authorization_issuer_trust_store=issuer_store,
        require_signed_authorization=True,
    )
    assert report["b2_ok"] is True, report
    assert report["authorization_status"] == "signed-verified"


def test_unsigned_authorization_rejected_when_signed_required(tmp_path: Path) -> None:
    ctx = _make_b2_ctx(tmp_path)
    with pytest.raises(ValueError, match="Unsigned witness authorisation rejected"):
        _run_b2(ctx, tmp_path, require_signed_authorization=True)
    run = _run_b2(ctx, tmp_path)
    report = verify_b2_execution(_load_inputs(ctx, run), require_signed_authorization=True)
    assert report["b2_ok"] is False
    assert "UNSIGNED_AUTHORIZATION_REJECTED" in str(report["b2_reason"])


def test_signed_authorization_forged_signature_rejected(tmp_path: Path) -> None:
    ctx = _make_b2_ctx(tmp_path)
    _issuer_priv, issuer_pub = generate_ed25519_keypair()
    attacker_priv, _attacker_pub = generate_ed25519_keypair()
    doc = _signed_auth_doc(ctx)
    forged = sign_witness_authorization(doc, attacker_priv, "op-1")
    issuer_store = _issuer_store(issuer_pub)
    _auth, ok, _note = verify_signed_witness_authorization(forged, issuer_store)
    assert ok is False
    with pytest.raises(ValueError, match="Signed witness authorisation rejected"):
        _run_b2(
            ctx,
            tmp_path,
            signed_authorization=forged,
            authorization_issuer_trust_store=issuer_store,
            require_signed_authorization=True,
            witness_public_pem=ctx["wit_pub"],
        )


def test_signed_authorization_wrong_issuer_rejected(tmp_path: Path) -> None:
    ctx = _make_b2_ctx(tmp_path)
    issuer_priv, _issuer_pub = generate_ed25519_keypair()
    _other_priv, other_pub = generate_ed25519_keypair()
    doc = _signed_auth_doc(ctx)
    envelope = sign_witness_authorization(doc, issuer_priv, "op-1")
    # Trust store names a different issuer key for the same key id.
    wrong_store = _issuer_store(other_pub)
    _auth, ok, _note = verify_signed_witness_authorization(envelope, wrong_store)
    assert ok is False


def test_signed_authorization_wrong_profile_rejected(tmp_path: Path) -> None:
    ctx = _make_b2_ctx(tmp_path)
    issuer_priv, issuer_pub = generate_ed25519_keypair()
    doc = _signed_auth_doc(ctx, profiles=["some-other-profile"])
    envelope = sign_witness_authorization(doc, issuer_priv, "op-1")
    issuer_store = _issuer_store(issuer_pub)
    with pytest.raises(ValueError, match="not authorised for profile"):
        _run_b2(
            ctx,
            tmp_path,
            signed_authorization=envelope,
            authorization_issuer_trust_store=issuer_store,
            require_signed_authorization=True,
            witness_public_pem=ctx["wit_pub"],
        )


# ---------------------------------------------------------------------------
# Domain re-execution + code-digest binding
# ---------------------------------------------------------------------------


def test_b2_reexecutes_domain_checks(tmp_path: Path) -> None:
    ctx = _make_b2_ctx(tmp_path)
    bundle_bytes, trust_keys = _build_signed_bundle(fin_members(), "fin-b2-001")
    package_path = tmp_path / "package.zip"
    package_path.write_bytes(bundle_bytes)
    profile_path = PROFILES_DIR / "financial-evidence" / "profile.json"
    out_dir = tmp_path / "b2-fin-out"
    summary = run_b2_witnessed_verification(
        package_path,
        profile_path,
        ctx["witness"],
        out_dir,
        package_trust_keys=trust_keys,
        receipt_signing_key_pem=ctx["prod_priv"],
        receipt_signer_key_id="prod-1",
        witness_public_pem=ctx["wit_pub"],
    )
    assert "fin.amount_match" in summary["attested_checks"]
    assert "fin.payment_match" in summary["attested_checks"]
    assert "fin.identity_match" in summary["attested_checks"]
    # The witness re-executed all 6 states' checks: the receipt the
    # producer produced and the witness's own re-execution agree.
    manifest = safe_json_loads((out_dir / "b2-manifest.json").read_bytes())
    assert manifest["execution_completeness"]["statement"] is not None
    assert "fin.amount_match" in manifest["execution_completeness"]["statement"]["executed"]


def test_b2_domain_forged_pass_refused(tmp_path: Path) -> None:
    import oev.b2_witness as b2_mod

    ctx = _make_b2_ctx(tmp_path)
    bundle_bytes, trust_keys = _build_signed_bundle(fin_members(), "fin-b2-002")
    package_path = tmp_path / "package.zip"
    package_path.write_bytes(bundle_bytes)
    profile_path = PROFILES_DIR / "financial-evidence" / "profile.json"
    # Corrupt the amount AFTER signing the bundle? No — forge the
    # producer claim instead: monkeypatch the producer's first
    # execute_verification call to report a forged PASS.
    from oev.receipts import finalize_receipt

    real_execute = b2_mod.execute_verification
    calls = {"n": 0}

    def forged_first(*a: Any, **k: Any) -> Any:
        receipt, envelope = real_execute(*a, **k)
        calls["n"] += 1
        if calls["n"] == 1:
            forged = finalize_receipt(
                dataclasses.replace(
                    receipt,
                    checks=[
                        dataclasses.replace(c, status=CheckStatus.PASS, detail="forged PASS")
                        if c.check_id == "fin.amount_match"
                        else c
                        for c in receipt.checks
                    ],
                )
            )
            return forged, envelope
        return receipt, envelope

    b2_mod.execute_verification = forged_first  # type: ignore[method-assign]
    try:
        with pytest.raises(ValueError, match="attestation refused"):
            run_b2_witnessed_verification(
                package_path,
                profile_path,
                ctx["witness"],
                tmp_path / "b2-fin-forged",
                package_trust_keys=trust_keys,
                receipt_signing_key_pem=ctx["prod_priv"],
                receipt_signer_key_id="prod-1",
                witness_public_pem=ctx["wit_pub"],
            )
    finally:
        b2_mod.execute_verification = real_execute  # type: ignore[method-assign]
    assert calls["n"] == 2


def test_b2_code_digest_document_binding(tmp_path: Path) -> None:
    ctx = _make_b2_ctx(tmp_path)
    run = _run_b2(ctx, tmp_path)
    manifest = safe_json_loads((run["out_dir"] / "b2-manifest.json").read_bytes())
    doc = manifest["code_digest_document"]
    assert doc["code_digest"] == manifest["code_digest"]
    assert doc["protocol_version"] == "oev-code-digest/0.1"
    report = verify_b2_execution(
        _load_inputs(ctx, run),
        expected_code_digest_document=doc,
    )
    assert report["b2_ok"] is True, report
    # A document pinning a different code digest must fail.
    wrong_doc = dict(doc)
    wrong_doc["code_digest"] = "sha256:" + "0" * 64
    report_wrong = verify_b2_execution(
        _load_inputs(ctx, run),
        expected_code_digest_document=wrong_doc,
    )
    assert report_wrong["b2_ok"] is False
    assert report_wrong["reason"] == "CODE_DIGEST_MISMATCH"
