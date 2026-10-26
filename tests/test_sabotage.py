# SPDX-License-Identifier: Apache-2.0

"""Sabotage test suite for the Decision Evidence Pack (oev-decision-pack/0.2).

Every test plays the role of an attacker against a valid, signed pack or a
hostile archive and asserts the protocol fails closed:

1. Byte flips          — single-bit corruption in members, artifacts, manifest,
                         DSSE payload, and DSSE signature bytes.
2. ZIP traversal       — archive entries that attempt to escape the extraction
                         root (absolute, '..', backslash, nested traversal).
3. Duplicate members   — duplicate ZIP entries and duplicate manifest paths.
4. Signature stripping — removing manifest.dsse.json must surface as
                         unsigned/untrusted, never as silent success.
5. Signature replace   — attacker-key envelopes, with and without a spoofed
                         trusted keyid, and envelopes over rewritten manifests.
6. Manifest tampering  — digest flips and fully self-consistent manifest
                         rebuilds, with and without a signature / replay pin.
7. Replay injection    — evidence observed after the snapshot injected into a
                         pinned pack must refuse replay.

Neutral synthetic fixtures only. No finance workflows, no customer data.
"""

from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from oev.canonical import canonicalize_json
from oev.cli import main as cli_main
from oev.decision_pack import build_pack, sign_pack_manifest, verify_pack
from oev.dsse import compute_pae
from oev.pack_archive import (
    PackArchiveError,
    create_pack_archive,
    extract_pack_archive,
    inspect_pack_archive,
)
from oev.replay import (
    PACK_HASH_CHANGED,
    REPLAY_OK,
    SIGNATURE_UNTRUSTED,
    SNAPSHOT_LEAK,
    pin_pack,
    replay_snapshot,
)
from oev.signing import generate_ed25519_keypair, load_ed25519_private_key
from oev.trust import TrustStore
from tests.test_decision_pack import _build_tmp_pack, _write_source_dir
from tests.test_replay_safety import _bind_fixture_facts, _rewrite_member_and_manifest


def _flip_bit(path: Path, offset: int | None = None) -> None:
    """Flip one bit of a stored file. Defaults to the middle byte."""

    data = bytearray(path.read_bytes())
    if not data:
        pytest.fail(f"cannot flip bits in an empty file: {path}")
    idx = len(data) // 2 if offset is None else offset
    data[idx] ^= 0x01
    path.write_bytes(bytes(data))


def _sign_and_pinned_store(tmp_path: Path, pack_dir: Path, key_id: str = "sabotage-key") -> Path:
    """Sign the pack with a fresh keypair and write the matching trust roots."""

    private_pem, public_pem = generate_ed25519_keypair()
    tmp_path.joinpath("signing-key.pem").write_bytes(private_pem)
    keys_path = tmp_path / "trust-keys.json"
    keys_path.write_bytes(
        canonicalize_json([{"key_id": key_id, "public_key_pem": public_pem.decode()}])
    )
    sign_pack_manifest(pack_dir, private_pem, key_id=key_id)
    return keys_path


# ---------------------------------------------------------------------------
# 1. Byte flips
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "member",
    [
        "case.json",
        "facts.json",
        "rule_runs.json",
        "findings.json",
        "review_actions.json",
        "timeline.json",
        "snapshot_context.json",
        "artifacts/notes.txt",
    ],
)
def test_single_bit_flip_in_member_breaks_verification(tmp_path: Path, member: str) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    _flip_bit(pack_dir / member)

    result = verify_pack(pack_dir)
    assert result.overall == "PACK_INVALID"
    flagged = [m for m in result.member_results if m.path == member]
    assert flagged and flagged[0].status in {"DIGEST_MISMATCH", "NOT_CANONICAL", "UNREADABLE"}


@pytest.mark.parametrize("which", ["payload", "signature"])
def test_single_bit_flip_in_dsse_envelope(tmp_path: Path, which: str) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    _sign_and_pinned_store(tmp_path, pack_dir)

    envelope_path = pack_dir / "manifest.dsse.json"
    raw = envelope_path.read_bytes()
    if which == "payload":
        anchor = raw.index(b'"payload":"') + len(b'"payload":"') + 10
    else:
        anchor = raw.index(b'"sig":"') + len(b'"sig":"') + 10
    _flip_bit(envelope_path, anchor)

    result = verify_pack(pack_dir)
    assert result.is_signed is True
    assert result.signature_crypto_valid is False
    assert result.is_trusted_signer is False
    if which == "payload":
        # The payload no longer equals the stored manifest bytes: the pack
        # itself is invalid, not just the signature.
        assert result.overall == "PACK_INVALID"
    else:
        # The envelope covers only the manifest; a broken signature bytes do
        # not corrupt member integrity — trust fails, integrity holds.
        assert result.overall == "PACK_VALID"


def test_single_bit_flip_in_manifest_bytes(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    _flip_bit(pack_dir / "manifest.json")
    result = verify_pack(pack_dir)
    assert result.overall == "PACK_INVALID"
    assert not result.pack_digest_valid or not result.manifest_canonical


def test_bit_flipped_member_then_replay_refuses(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    pin = pin_pack(pack_dir)
    _flip_bit(pack_dir / "facts.json")
    replayed = replay_snapshot(pack_dir, expected_pack_digest=pin["pack_digest"])
    assert replayed.replay_status == "PACK_INVALID"


# ---------------------------------------------------------------------------
# 2. ZIP traversal entries
# ---------------------------------------------------------------------------


def _write_zip(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for name, body in entries:
            zf.writestr(name, body)


def test_zip_traversal_entries_are_rejected_before_extraction(tmp_path: Path) -> None:
    hostile = tmp_path / "hostile.zip"
    _write_zip(
        hostile,
        [
            ("case.json", b"{}"),
            ("../evil-outside.txt", b"escaped"),
        ],
    )
    out_dir = tmp_path / "out"
    with pytest.raises(PackArchiveError, match="traverses outside the root|absolute|forbidden"):
        extract_pack_archive(hostile, out_dir)
    assert not out_dir.exists()  # validation runs before any extraction
    assert not (tmp_path / "evil-outside.txt").exists()


@pytest.mark.parametrize(
    "name",
    [
        "/etc/oev-evil",  # absolute path
        "..\\windows-evil.txt",  # backslash separator
        "good/../../evil-nested.txt",  # traversal after a safe prefix
        "good/./dot-segment.txt",  # relative segment
    ],
)
def test_zip_hostile_entry_names_rejected(tmp_path: Path, name: str) -> None:
    hostile = tmp_path / "hostile.zip"
    _write_zip(hostile, [(name, b"payload")])
    with pytest.raises(PackArchiveError):
        inspect_pack_archive(hostile)


def test_zip_traversal_never_writes_outside_root(tmp_path: Path) -> None:
    """Even a mixed archive (safe prefix + hostile tail) extracts nothing."""

    hostile = tmp_path / "mixed.zip"
    _write_zip(
        hostile,
        [
            ("case.json", b"first"),
            ("facts.json", b"second"),
            ("artifacts/../../escape.txt", b"escaped"),
        ],
    )
    out_dir = tmp_path / "out"
    with pytest.raises(PackArchiveError):
        extract_pack_archive(hostile, out_dir)
    assert not out_dir.exists()  # validation runs before any extraction
    assert not (tmp_path / "escape.txt").exists()


def test_zip_encrypted_entry_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "pack.zip"
    pack_dir = _build_tmp_pack(tmp_path, "enc-src-pack")
    create_pack_archive(pack_dir, archive)

    # Force the encryption flag on the case.json central-directory record.
    # (zipfile.writestr silently drops the bit, so patch raw bytes: the
    # general-purpose flag is the 2-byte little-endian field at offset 8 of
    # each PK\x01\x02 record, and the filename starts at offset 46.)
    raw = bytearray(archive.read_bytes())
    patched = False
    for i in range(len(raw) - 4):
        if raw[i : i + 4] == b"PK\x01\x02" and raw[i + 46 : i + 46 + 9] == b"case.json":
            raw[i + 8] |= 0x01
            patched = True
            break
    assert patched, "central directory record for case.json not found"
    hostile = tmp_path / "encrypted.zip"
    hostile.write_bytes(bytes(raw))

    with pytest.raises(PackArchiveError, match="encrypted"):
        inspect_pack_archive(hostile)


def test_zip_size_bound_rejects_decompression_bomb(tmp_path: Path) -> None:
    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("artifacts/bomb.bin", b"\x00" * (65 * 1024 * 1024))
    with pytest.raises(PackArchiveError, match="size bound"):
        inspect_pack_archive(bomb)


# ---------------------------------------------------------------------------
# 3. Duplicate members
# ---------------------------------------------------------------------------


@pytest.mark.filterwarnings("ignore:Duplicate name:UserWarning")
def test_zip_duplicate_entry_names_rejected(tmp_path: Path) -> None:
    dup = tmp_path / "dup.zip"
    with zipfile.ZipFile(dup, "w") as zf:
        zf.writestr("case.json", b"first version")
        zf.writestr("case.json", b"shadowing version")
        zf.writestr("facts.json", b"{}")

    with pytest.raises(PackArchiveError, match="duplicate entry name: 'case.json'"):
        inspect_pack_archive(dup)

    out_dir = tmp_path / "out"
    with pytest.raises(PackArchiveError, match="duplicate"):
        extract_pack_archive(dup, out_dir)
    if out_dir.exists():
        assert list(out_dir.iterdir()) == []


def test_manifest_duplicate_member_paths_rejected(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    manifest_path = pack_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    duplicate = json.loads(json.dumps(manifest["members"][0]))
    manifest["members"].append(duplicate)
    body = dict(manifest)
    body.pop("pack_digest")
    manifest["pack_digest"] = "sha256:" + hashlib.sha256(canonicalize_json(body)).hexdigest()
    manifest_path.write_bytes(canonicalize_json(manifest))

    result = verify_pack(pack_dir)
    assert result.overall == "PACK_INVALID"
    assert result.member_order_stable is False
    # Rejection surfaces through the schema (uniqueItems) and/or the stable
    # order check — either way the duplicate pack never verifies.
    assert result.reasons


# ---------------------------------------------------------------------------
# 4. Signature stripping
# ---------------------------------------------------------------------------


def test_signature_stripping_is_surfaced_never_silent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    keys_path = _sign_and_pinned_store(tmp_path, pack_dir)
    trust = TrustStore.from_file(keys_path)

    before = verify_pack(pack_dir, trust_store=trust)
    assert before.overall == "PACK_VALID" and before.is_trusted_signer

    (pack_dir / "manifest.dsse.json").unlink()

    after = verify_pack(pack_dir, trust_store=trust)
    assert after.overall == "PACK_VALID"  # integrity holds
    assert after.is_signed is False  # ...but the strip is visible
    assert after.is_trusted_signer is False
    assert after.signature_crypto_valid is False

    # A caller who pinned trust roots gets a hard failure, not silence.
    rc = cli_main(["pack", "verify", str(pack_dir), "--verifier-keys", str(keys_path)])
    assert rc == 2

    # And replay under pinned roots refuses outright.
    result = replay_snapshot(pack_dir, trust_store=trust)
    assert result.replay_status == SIGNATURE_UNTRUSTED


# ---------------------------------------------------------------------------
# 5. Signature replacement
# ---------------------------------------------------------------------------


def test_signature_replaced_by_attacker_key_with_spoofed_keyid(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    keys_path = _sign_and_pinned_store(tmp_path, pack_dir, key_id="trusted-signer")
    trust = TrustStore.from_file(keys_path)

    # Attacker keeps the payload (it must match the manifest) but re-signs
    # with their own key while spoofing the trusted keyid.
    attacker_pem, _attacker_public = generate_ed25519_keypair()
    attacker_key = load_ed25519_private_key(attacker_pem)
    manifest_bytes = (pack_dir / "manifest.json").read_bytes()
    payload_type = "application/vnd.oev.decision-pack-manifest+json"
    envelope = {
        "payloadType": payload_type,
        "payload": base64.b64encode(manifest_bytes).decode("ascii"),
        "signatures": [
            {
                "sig": base64.b64encode(
                    attacker_key.sign(compute_pae(payload_type, manifest_bytes))
                ).decode("ascii"),
                "keyid": "trusted-signer",  # spoofed hint
            }
        ],
    }
    (pack_dir / "manifest.dsse.json").write_bytes(canonicalize_json(envelope))

    result = verify_pack(pack_dir, trust_store=trust)
    assert result.overall == "PACK_VALID"  # member integrity intact
    assert result.is_signed is True
    assert result.signature_crypto_valid is False  # spoof detected
    assert result.is_trusted_signer is False
    assert result.trusted_signer_key_id is None

    assert replay_snapshot(pack_dir, trust_store=trust).replay_status == SIGNATURE_UNTRUSTED


def test_signature_replaced_over_rewritten_manifest_is_invalid(tmp_path: Path) -> None:
    """Attacker rewrites a member coherently and re-signs the new manifest.

    Without the trusted key they cannot forge trust: the replaced signature is
    not trusted, and replay under pinned roots refuses.
    """

    pack_dir = _build_tmp_pack(tmp_path)
    keys_path = _sign_and_pinned_store(tmp_path, pack_dir, key_id="trusted-signer")
    trust = TrustStore.from_file(keys_path)
    pin = pin_pack(pack_dir)

    doc = json.loads((pack_dir / "findings.json").read_bytes())
    doc["findings"][0]["severity"] = "CRITICAL"
    _rewrite_member_and_manifest(pack_dir, "findings.json", doc)

    # Re-sign the rewritten manifest with a fresh attacker key.
    attacker_private, _ = generate_ed25519_keypair()
    sign_pack_manifest(pack_dir, attacker_private, key_id="trusted-signer")

    result = verify_pack(pack_dir, trust_store=trust)
    assert result.is_signed is True
    assert result.is_trusted_signer is False  # keyid is only a hint

    # The original signature pinned the original bytes; the pin refuses.
    assert (
        replay_snapshot(
            pack_dir, expected_pack_digest=pin["pack_digest"], trust_store=trust
        ).replay_status
        == PACK_HASH_CHANGED
    )


# ---------------------------------------------------------------------------
# 6. Manifest tampering
# ---------------------------------------------------------------------------


def test_manifest_member_digest_flip_detected(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    manifest_path = pack_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    entry = next(m for m in manifest["members"] if m["path"] == "facts.json")
    hex_part = entry["sha256"].split(":", 1)[1]
    flipped = ("0" if hex_part[0] != "0" else "1") + hex_part[1:]
    entry["sha256"] = "sha256:" + flipped
    # Deliberately WITHOUT recomputing pack_digest: the declared self-digest
    # no longer matches the tampered body.
    manifest_path.write_bytes(canonicalize_json(manifest))

    result = verify_pack(pack_dir)
    assert result.overall == "PACK_INVALID"
    assert result.pack_digest_valid is False


def test_self_consistent_manifest_rebuild_without_signature(tmp_path: Path) -> None:
    """Honest limitation: an unsigned, coherently rewritten pack verifies.

    Only an out-of-band replay pin (or a manifest signature) catches this —
    which is exactly why pins exist.
    """

    pack_dir = _build_tmp_pack(tmp_path)
    pin = pin_pack(pack_dir)

    doc = json.loads((pack_dir / "timeline.json").read_bytes())
    doc["events"][0]["summary"] = "Attacker-approved summary."
    _rewrite_member_and_manifest(pack_dir, "timeline.json", doc)

    assert verify_pack(pack_dir).overall == "PACK_VALID"
    assert replay_snapshot(pack_dir).replay_status == REPLAY_OK  # no pin, no proof
    result = replay_snapshot(pack_dir, expected_pack_digest=pin["pack_digest"])
    assert result.replay_status == PACK_HASH_CHANGED


def test_self_consistent_manifest_rebuild_with_signature_breaks_binding(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    _sign_and_pinned_store(tmp_path, pack_dir)

    doc = json.loads((pack_dir / "facts.json").read_bytes())
    doc["facts"][0]["value"] = False
    _rewrite_member_and_manifest(pack_dir, "facts.json", doc)

    result = verify_pack(pack_dir)
    assert result.overall == "PACK_INVALID"
    assert any("payload does not match" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# 7. Replay with later evidence injected
# ---------------------------------------------------------------------------


def _pack_with_late_fact(tmp_path: Path, name: str, consume: bool) -> Path:
    """Build a self-consistent pack containing post-snapshot evidence."""

    src = tmp_path / f"{name}-src"
    src.mkdir()
    _write_source_dir(src)
    _bind_fixture_facts(src)

    facts = json.loads((src / "facts.json").read_bytes())
    facts["facts"].append(
        {
            "fact_id": "fact-after-snapshot",
            "key": "sensor.reading_after_capture",
            "value": "99.9",
            "value_type": "decimal_string",
            "source": "sensor-feed-A",
            "observed_at": "2026-02-01T00:00:00Z",  # captured_at is 2026-01-01T00:00:00Z
            "snapshot_source_id": "source-001",
        }
    )
    (src / "facts.json").write_bytes(canonicalize_json(facts))

    if consume:
        runs = json.loads((src / "rule_runs.json").read_bytes())
        runs["rule_runs"][0]["inputs"].append("fact-after-snapshot")
        (src / "rule_runs.json").write_bytes(canonicalize_json(runs))

    out = tmp_path / name
    build_pack(src, out, pack_id=f"pack-{name}", created_at="2026-03-01T00:00:00Z")
    return out


def test_replay_with_later_evidence_injected_refuses_via_pin(tmp_path: Path) -> None:
    original = _build_tmp_pack(tmp_path, "original-pack")
    pin = pin_pack(original)

    # "Later evidence appears" — a new pack build that includes a fact the
    # snapshot never contained, replayed under the original pin.
    injected = _pack_with_late_fact(tmp_path, "injected", consume=False)
    assert verify_pack(injected).overall == "PACK_VALID"  # self-consistent...

    result = replay_snapshot(injected, expected_pack_digest=pin["pack_digest"])
    assert result.replay_status == PACK_HASH_CHANGED  # ...but not the pinned pack


def test_replay_in_place_injection_into_pinned_pack(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    pin = pin_pack(pack_dir)

    facts = json.loads((pack_dir / "facts.json").read_bytes())
    facts["facts"].append(
        {
            "fact_id": "fact-injected-later",
            "key": "sensor.reading_after_capture",
            "value": "99.9",
            "value_type": "decimal_string",
            "source": "sensor-feed-A",
            "observed_at": "2026-02-01T00:00:00Z",
            "snapshot_source_id": "source-001",
        }
    )
    _rewrite_member_and_manifest(pack_dir, "facts.json", facts)

    result = replay_snapshot(pack_dir, expected_pack_digest=pin["pack_digest"])
    assert result.replay_status == PACK_HASH_CHANGED
    # And even unpinned, the late fact itself never enters the replay scope.
    unpinned = replay_snapshot(pack_dir)
    assert "fact-injected-later" not in unpinned.eligible_fact_ids


def test_replay_refuses_when_recorded_run_consumed_later_evidence(tmp_path: Path) -> None:
    pack_dir = _pack_with_late_fact(tmp_path, "leaky", consume=True)
    result = replay_snapshot(pack_dir)
    assert result.replay_status == SNAPSHOT_LEAK
    assert "fact-after-snapshot" not in result.eligible_fact_ids


def test_cli_replay_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    keys_path = _sign_and_pinned_store(tmp_path, pack_dir)
    pin = pin_pack(pack_dir)

    rc = cli_main(
        [
            "pack",
            "replay",
            str(pack_dir),
            "--expect-pack-digest",
            pin["pack_digest"],
            "--verifier-keys",
            str(keys_path),
        ]
    )
    assert rc == 0

    doc = json.loads((pack_dir / "case.json").read_bytes())
    doc["case_type"] = "tampered-after-pin"
    _rewrite_member_and_manifest(pack_dir, "case.json", doc)

    # The stale DSSE envelope no longer binds the rewritten manifest, so the
    # pack itself is invalid and replay exits 1.
    rc = cli_main(
        [
            "pack",
            "replay",
            str(pack_dir),
            "--expect-pack-digest",
            pin["pack_digest"],
            "--verifier-keys",
            str(keys_path),
        ]
    )
    assert rc == 1
    assert "PACK_INVALID" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Archive round-trip (control group for the ZIP attacks)
# ---------------------------------------------------------------------------


def test_archive_round_trip_preserves_pack_and_is_deterministic(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    archive_a = tmp_path / "pack-a.zip"
    archive_b = tmp_path / "pack-b.zip"
    create_pack_archive(pack_dir, archive_a)
    create_pack_archive(pack_dir, archive_b)
    assert archive_a.read_bytes() == archive_b.read_bytes()  # deterministic bytes

    out = tmp_path / "restored"
    extracted = extract_pack_archive(archive_a, out)
    assert "manifest.json" in extracted
    assert verify_pack(out).overall == "PACK_VALID"
