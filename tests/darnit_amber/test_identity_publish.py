"""Tests for ``--identity`` (Fulcio) signing and ``--publish`` (Rekor): the parts of a run bundle that say who
signed it and let anyone confirm it from the public log. The key-signed bundle itself is tested in
``test_run_bundle``; its helpers and fixtures are reused here. No witness binary needed."""

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from darnit_amber import run as amber_run
from darnit_amber.cli import main

from tests.darnit_amber.test_run_bundle import (
    _bundle,
    _execute,
    _key_bundle,
    _key_envelope,
    _stamps_for,
    _write_pub,
)


def test_publish_failure_keeps_the_stored_bundle(repo, no_signing, monkeypatch):
    """A failed --publish lost the whole run (review): now the bundle is stored first and the error names it."""

    def boom(env, key, url):
        raise ConnectionError("rekor down")

    monkeypatch.setattr("darnit_amber.publish.publish_envelope", boom)
    with pytest.raises(amber_run.RunError, match=r"bundle (\w+) is stored; publishing to .* failed: ConnectionError"):
        _execute(repo, no_signing, {"o.txt": b"x"}, {"run": {"command": "true"}}, publish="https://rekor.example")
    (stored,) = list(no_signing._root.glob("*.intoto.json"))
    assert json.loads(stored.read_bytes())["publication"] is None


def test_run_publishes_the_statement_and_every_envelope(repo, no_signing, monkeypatch):
    sent = []
    monkeypatch.setattr(
        "darnit_amber.publish.publish_envelope",
        lambda e, key, url: (
            sent.append(url) or {"log": url, "uuid": "u", "log_index": len(sent), "integrated_time": 1, "response": {}}
        ),
    )
    bundle = _execute(repo, no_signing, {"o.txt": b"x"}, {"run": {"command": "true"}}, publish="https://rekor.example")
    assert sent == ["https://rekor.example"] * 3
    assert set(bundle["publication"]) == {"statement", "amber-audit", "experiment"}
    assert "publication" not in bundle["statement"]["predicate"]  # outside the signed statement: stored first
    stored = json.loads((no_signing._root / f"{bundle['id']}.intoto.json").read_bytes())
    assert stored["publication"]["experiment"]["log_index"] == 3


def test_expected_identity_on_a_key_signed_bundle_fails(tmp_path, stamped):
    """--expect-identity was silently ignored on a key-signed bundle (review, Nov 11): now it is a failed check."""
    from darnit_amber import rerun as rr

    store, bundle, _researcher, pub = _key_bundle(tmp_path)
    assert rr.verify(store, bundle["id"], pub)["verified"] is True
    out = rr.verify(store, bundle["id"], pub, expect_identity="someone@example.org", expect_issuer="https://x")
    assert out["verified"] is False
    assert "identity was expected" in out["signatures"]["statement"]["signature"]


def test_expect_published_fails_an_unpublished_bundle(tmp_path, stamped):
    from darnit_amber import rerun as rr

    store, bundle, _researcher, pub = _key_bundle(tmp_path)
    assert rr.verify(store, bundle["id"], pub)["verified"] is True
    out = rr.verify(store, bundle["id"], pub, expect_published=True)
    assert out["published"] is False and out["verified"] is False


# --- --identity (Fulcio): the verification path, with a chain made here instead of a login ---

_ROOT_KEYS: dict = {}


def serialization_pem():
    from cryptography.hazmat.primitives import serialization

    return serialization.Encoding.PEM


def _root_key_of(root):
    return _ROOT_KEYS[root.public_bytes(serialization_pem())]


def _make_chain(email="marc@example.edu", issuer="https://github.com/login/oauth"):
    """A root CA and a ten-minute leaf shaped like Fulcio's, valid around NOW."""
    from datetime import timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.now(UTC).replace(microsecond=0)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _fulcio_shaped_leaf(leaf_key.public_key(), root, root_key, email, issuer, now)
    _ROOT_KEYS[root.public_bytes(serialization_pem())] = root_key
    return root, leaf, leaf_key, now


def _fulcio_shaped_leaf(public_key, issuer_cert, issuer_key, email, issuer, now, *, eku=True):
    """A ten-minute leaf like Fulcio's: empty subject, SAN email, issuer OID, code-signing EKU, SKI/AKI."""
    from datetime import timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier

    der_utf8 = bytes([0x0C, len(issuer)]) + issuer.encode()
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=9))
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=True)
        .add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.57264.1.8"), der_utf8), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False)
    )
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def _identity_envelope(leaf, leaf_key, payload=b'{"hello":"world"}', payload_type="application/vnd.in-toto+json"):
    return _key_envelope(leaf_key, payload, payload_type, certificate=leaf)


def test_certificate_identity_reads_san_and_fulcio_issuer():
    from darnit_amber.identity import certificate_identity

    _root, leaf, _key, _now = _make_chain()
    who = certificate_identity(leaf)
    assert who["subject"] == "marc@example.edu"
    assert who["issuer"] == "https://github.com/login/oauth"
    assert len(who["certificate_sha256"]) == 64


def test_identity_signature_verifies_inside_the_window_against_the_trusted_root():
    from datetime import timedelta

    from darnit_amber.identity import verify_identity_signature

    root, leaf, key, now = _make_chain()
    env = _identity_envelope(leaf, key)
    sig = env["signatures"][0]
    good = verify_identity_signature(env, sig, now, [root])
    assert good["signature"] == "ok" and good["chain"] == "ok" and good["ok"] is True
    assert good["subject"] == "marc@example.edu"

    late = verify_identity_signature(env, sig, now + timedelta(hours=1), [root])
    assert late["signature"] == "ok" and late["ok"] is False and "no valid path" in late["chain"]

    other_root, _l, _k, _n = _make_chain()
    stranger = verify_identity_signature(env, sig, now, [other_root])
    assert stranger["ok"] is False and "no valid path" in stranger["chain"]

    untimed = verify_identity_signature(env, sig, None, [root])
    assert untimed["ok"] is False and untimed["chain"].startswith("skipped")


def test_identity_signature_rejects_a_tampered_payload():
    from darnit_amber.identity import verify_identity_signature

    root, leaf, key, now = _make_chain()
    env = _identity_envelope(leaf, key)
    env["payload"] = base64.b64encode(b'{"hello":"mars"}').decode()
    assert verify_identity_signature(env, env["signatures"][0], now, [root])["signature"].startswith("invalid")


def _identity_bundle(tmp_path, monkeypatch, email="marc@example.edu"):
    from darnit_amber import rerun as rr
    from darnit_amber.identity import certificate_identity
    from darnit_amber.run import STATEMENT_TYPE

    root, leaf, key, now = _make_chain(email=email)
    monkeypatch.setattr(rr, "_timestamps", lambda env: [{**s, "time": now.isoformat()} for s in _stamps_for(env)])

    class Root:
        def get_fulcio_certs(self):
            return [root]

    monkeypatch.setattr(rr, "_TRUST_ROOT", Root())
    env = _identity_envelope(leaf, key)
    predicate = {
        "signing": {
            "method": "identity",
            "identity": email,
            "issuer": "https://github.com/login/oauth",
            "certificates_sha256": {"amber-audit": certificate_identity(leaf)["certificate_sha256"]},
        }
    }
    store, bundle = _bundle(
        tmp_path, predicate, lambda c: _identity_envelope(leaf, key, c, STATEMENT_TYPE), {"amber-audit": env}
    )
    return store, bundle, root, leaf, key


def test_identity_bundle_needs_the_expected_identity(monkeypatch, tmp_path):
    """Anyone pinning a researcher's identity accepted a bundle from any Fulcio identity (review B8)."""
    from darnit_amber import rerun as rr

    store, bundle, root, leaf, key = _identity_bundle(tmp_path, monkeypatch)
    bid = bundle["id"]
    unpinned = rr.verify(store, bid, None)
    assert unpinned["signatures"]["statement"]["subject"] == "marc@example.edu"
    assert "no expected identity" in unpinned["signatures"]["statement"]["signature"]
    assert unpinned["verified"] is False

    good = rr.verify(
        store, bid, None, expect_identity="marc@example.edu", expect_issuer="https://github.com/login/oauth"
    )
    assert all(s["ok"] for s in good["signatures"].values())
    assert good["statement_signed"] is True and good["signatures_verified"] is True and good["verified"] is True

    stranger = rr.verify(
        store, bid, None, expect_identity="someone@else.edu", expect_issuer="https://github.com/login/oauth"
    )
    assert (
        stranger["verified"] is False
        and "not the expected identity" in stranger["signatures"]["statement"]["signature"]
    )

    # --pubkey on a certificate-signed bundle was ignored: now it must be the key in the certificate
    from cryptography.hazmat.primitives.asymmetric import ec

    _write_pub(ec.generate_private_key(ec.SECP256R1()), tmp_path / "unrelated.pub")
    with_key = rr.verify(
        store,
        bid,
        tmp_path / "unrelated.pub",
        expect_identity="marc@example.edu",
        expect_issuer="https://github.com/login/oauth",
    )
    assert (
        with_key["verified"] is False
        and "--pubkey is not the key in the certificate" in with_key["signatures"]["statement"]["signature"]
    )


def test_identity_in_the_statement_must_match_the_certificate(monkeypatch, tmp_path):
    """signing.identity was rewritten to another address next to the real certificate, and nothing compared them (review B1)."""
    from darnit_amber import rerun as rr

    store, bundle, root, leaf, key = _identity_bundle(tmp_path, monkeypatch)
    bundle["statement"]["predicate"]["signing"]["identity"] = "jcappos@nyu.edu"
    bundle["id"] = hashlib.sha256(amber_run._canonical(bundle["statement"])).hexdigest()
    store.write(bundle["id"], amber_run._canonical(bundle), "")
    out = rr.verify(
        store, bundle["id"], None, expect_identity="jcappos@nyu.edu", expect_issuer="https://github.com/login/oauth"
    )
    assert out["statement_signed"] is False  # the signed payload is the original statement
    assert "different identity" in out["signatures"]["amber-audit"]["signature"]
    assert out["verified"] is False


def test_swapped_envelope_from_another_honest_identity_is_not_this_bundle(monkeypatch, tmp_path):
    from darnit_amber import rerun as rr

    store, bundle, root, leaf, key = _identity_bundle(tmp_path, monkeypatch)
    _other_root, other_leaf, other_key, _ = _make_chain()
    swapped = {**bundle, "witness_envelopes": {"amber-audit": _identity_envelope(other_leaf, other_key)}}
    store.write(bundle["id"], amber_run._canonical(swapped), "")
    out = rr.verify(
        store, bundle["id"], None, expect_identity="marc@example.edu", expect_issuer="https://github.com/login/oauth"
    )
    assert out["envelopes_match_statement"] is False and out["verified"] is False


def test_identity_chain_rejects_a_leaf_issued_by_another_leaf():
    """Any Fulcio user could otherwise mint a certificate naming someone else and pass it as an intermediate."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from darnit_amber.identity import verify_identity_signature

    root, honest_leaf, honest_key, now = _make_chain(email="attacker@evil.example")
    forged_key = ec.generate_private_key(ec.SECP256R1())
    forged = _fulcio_shaped_leaf(forged_key.public_key(), honest_leaf, honest_key, "jcappos@nyu.edu", "https://x", now)
    env = _identity_envelope(forged, forged_key)
    sig = env["signatures"][0]
    sig["intermediates"] = [base64.b64encode(honest_leaf.public_bytes(serialization_pem())).decode()]
    out = verify_identity_signature(env, sig, now, [root])
    assert out["subject"] == "jcappos@nyu.edu"  # what the forged certificate claims
    assert out["signature"] == "ok"  # it is self-consistent
    assert out["ok"] is False and out["chain"] != "ok"  # but no CA issued it


def test_identity_chain_requires_the_code_signing_eku():
    from cryptography.hazmat.primitives.asymmetric import ec
    from darnit_amber.identity import verify_identity_signature

    root, _leaf, _key, now = _make_chain()
    key = ec.generate_private_key(ec.SECP256R1())
    no_eku = _fulcio_shaped_leaf(key.public_key(), root, _root_key_of(root), "a@b", "https://x", now, eku=False)
    env = _identity_envelope(no_eku, key)
    out = verify_identity_signature(env, env["signatures"][0], now, [root])
    assert out["ok"] is False and "key usage" in out["chain"]


def test_witness_signs_with_fulcio_when_given_a_token_file(monkeypatch, tmp_path):
    from darnit_amber import run as r

    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        raise FileNotFoundError

    monkeypatch.setattr(r.shutil, "which", lambda _: "/bin/witness")
    monkeypatch.setattr(r.subprocess, "run", fake_run)
    with pytest.raises(FileNotFoundError):
        r._witness("s", None, tmp_path / "o", tmp_path, ["true"], token_path=tmp_path / "tok")
    cmd = seen["cmd"]
    assert "-k" not in cmd
    assert cmd[cmd.index("--signer-fulcio-url") + 1] == "https://fulcio.sigstore.dev"
    assert cmd[cmd.index("--signer-fulcio-token-path") + 1] == str((tmp_path / "tok").resolve())
    assert "--signer-fulcio-token" not in cmd  # the token itself never goes on the command line


def test_identity_token_prefers_the_environment(monkeypatch):
    from darnit_amber.identity import TOKEN_ENV, identity_token

    monkeypatch.setenv(TOKEN_ENV, " eyJ.token ")
    assert identity_token() == "eyJ.token"


def test_identity_without_timestamp_is_refused(tmp_path, capsys):
    rc = main(["run", str(tmp_path), "--identity", "--no-timestamp", "--out", str(tmp_path / "out")])
    assert rc == 1
    assert "needs a timestamp" in capsys.readouterr().err


def test_witness_environment_never_carries_the_oidc_token(monkeypatch, tmp_path):
    from darnit_amber import run as r
    from darnit_amber.identity import TOKEN_ENV

    seen = {}

    def fake_run(cmd, **kw):
        seen["env"] = kw.get("env")
        raise FileNotFoundError

    monkeypatch.setenv(TOKEN_ENV, "secret")
    monkeypatch.setattr(r.shutil, "which", lambda _: "/bin/witness")
    monkeypatch.setattr(r.subprocess, "run", fake_run)
    with pytest.raises(FileNotFoundError):
        r._witness("s", None, tmp_path / "o", tmp_path, ["true"], token_path=tmp_path / "tok")
    assert TOKEN_ENV not in seen["env"]
    assert seen["env"]["PATH"].split(":")[0] == str(Path(r.sys.executable).parent)  # darnit's own bin dir leads PATH


# --- real bundles made on the darnit VM (see the fixtures' README): verifiable forever because verify uses the
# timestamp's time, and offline because the trusted root is the copy sigstore-python ships ---

FIXTURE_IDENTITY = "fcaecc716ae5ebc4acc2ca53b5e823bc4743978633e257a823a4f0152bfb4aef"
FIXTURE_IDENTITY_SUBJECT = ("md6796@nyu.edu", "https://github.com/login/oauth")
FIXTURE_PUBLISHED = "c3e2fda5054fc34e3dc2b3f7f6596f0a14055064e9206b9a87705dfa399a35f4"
FIXTURE_PUBLISHED_LOG_INDEXES = {"statement": 3691869540, "amber-audit": 3691869544, "experiment": 3691869564}


@pytest.fixture
def offline_root(monkeypatch):
    from darnit_amber import rerun as rr
    from sigstore.models import ClientTrustConfig

    monkeypatch.setattr(rr, "_TRUST_ROOT", ClientTrustConfig.production(offline=True).trusted_root)


class FixtureStore:
    _root = Path(__file__).parent / "fixtures"


def test_real_identity_bundle_verifies_offline(offline_root):
    """A bundle signed with a real Fulcio certificate (GitHub login) and timestamped by Sigstore's TSA."""
    from darnit_amber import rerun as rr

    email, issuer = FIXTURE_IDENTITY_SUBJECT
    out = rr.verify(FixtureStore(), FIXTURE_IDENTITY, None, online=False, expect_identity=email, expect_issuer=issuer)
    assert out["statement_signed"] is True and out["envelopes_match_statement"] is True
    for name in ("statement", "amber-audit", "experiment"):
        who = out["signatures"][name]
        assert who["subject"] == email and who["issuer"] == issuer
        assert who["signature"] == "ok" and who["chain"] == "ok" and who["ok"] is True
    assert out["timestamps_trusted"] is True
    assert out["verified"] is True
    assert rr.verify(FixtureStore(), FIXTURE_IDENTITY, None, online=False)["verified"] is False  # identity not pinned


def test_real_published_bundle_verifies_offline(offline_root):
    """A key-signed bundle published to Rekor: signature with the fixture's public key, timestamp, inclusion proof."""
    from darnit_amber import rerun as rr

    out = rr.verify(FixtureStore(), FIXTURE_PUBLISHED, FixtureStore._root / "published-signing.pub", online=False)
    assert out["statement_signed"] is True and out["envelopes_match_statement"] is True
    assert {n: s["signature"] for n, s in out["signatures"].items()} == {
        "statement": "ok",
        "amber-audit": "ok",
        "experiment": "ok",
    }
    assert out["timestamps_trusted"] is True
    for name, index in FIXTURE_PUBLISHED_LOG_INDEXES.items():
        p = out["publication"][name]
        assert p["log_index"] == index
        assert p["entry_matches_envelope"] is True and p["inclusion"] == "ok" and p["online"] is None
    assert out["published"] is True
    assert out["verified"] is True


# --- --publish (Rekor) ---


def test_dsse_envelope_for_rekor_drops_witness_extras():
    from darnit_amber.publish import _dsse_envelope, _verifiers

    env = {
        "payload": "eA==",
        "payloadType": "t",
        "signatures": [{"keyid": "k", "sig": "c2ln", "certificate": "Q0VSVA==", "timestamps": [{"x": 1}]}],
    }
    assert json.loads(_dsse_envelope(env)) == {
        "payload": "eA==",
        "payloadType": "t",
        "signatures": [{"keyid": "k", "sig": "c2ln"}],
    }
    assert _verifiers(env, None) == ["Q0VSVA=="]  # the certificate is the verifier


def test_verifiers_for_a_key_signed_envelope_is_the_public_key(tmp_path, monkeypatch):
    from darnit_amber.publish import _verifiers

    monkeypatch.setattr("darnit_amber.run.user_data_root", lambda: tmp_path)
    key = amber_run.default_key()
    (verifier,) = _verifiers({"signatures": [{"sig": "c2ln"}]}, key)
    assert base64.b64decode(verifier).startswith(b"-----BEGIN PUBLIC KEY-----")
    with pytest.raises(ValueError):
        _verifiers({"signatures": [{"sig": "c2ln"}]}, None)


def _rekor_record(env, payload_hash=None, sigs=None):
    body = {
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "payloadHash": {
                "algorithm": "sha256",
                "value": payload_hash or hashlib.sha256(base64.b64decode(env["payload"])).hexdigest(),
            },
            "signatures": [{"signature": s, "verifier": "x"} for s in (sigs or [s["sig"] for s in env["signatures"]])],
        },
    }
    entry = {
        "body": base64.b64encode(json.dumps(body).encode()).decode(),
        "integratedTime": 1793000000,
        "logID": "ab",
        "logIndex": 7,
        "verification": {},
    }
    return {
        "log": "https://rekor.example",
        "uuid": "u",
        "log_index": 7,
        "integrated_time": 1793000000,
        "response": {"u": entry},
    }


def test_verify_publication_matches_entry_to_envelope_before_the_proof(monkeypatch):
    from darnit_amber import publish as pub

    env = {"payload": "eA==", "payloadType": "t", "signatures": [{"keyid": "k", "sig": "c2ln"}]}

    class Entry:
        @classmethod
        def _from_v1_response(cls, response):
            return cls()

        def _verify(self, keyring):
            return None

    class Root:
        def rekor_keyring(self, purpose):
            return object()

    monkeypatch.setattr("sigstore.models.TransparencyLogEntry", Entry)
    good = pub.verify_publication(env, _rekor_record(env), Root(), online=False)
    assert good["entry_matches_envelope"] is True and good["inclusion"] == "ok" and good["ok"] is True
    assert good["integrated_time"].startswith("2026-10-")
    assert good["online"] is None

    other = pub.verify_publication(env, _rekor_record(env, payload_hash="00" * 32), Root(), online=False)
    assert other["entry_matches_envelope"] is False and other["ok"] is False and other["inclusion"] is None

    forged = pub.verify_publication(env, _rekor_record(env, sigs=["b3RoZXI="]), Root(), online=False)
    assert forged["ok"] is False


def test_verify_publication_reports_a_bad_proof(monkeypatch):
    from darnit_amber import publish as pub

    env = {"payload": "eA==", "payloadType": "t", "signatures": [{"keyid": "k", "sig": "c2ln"}]}

    class Entry:
        @classmethod
        def _from_v1_response(cls, response):
            return cls()

        def _verify(self, keyring):
            raise ValueError("inclusion proof contains invalid root hash")

    class Root:
        def rekor_keyring(self, purpose):
            return object()

    monkeypatch.setattr("sigstore.models.TransparencyLogEntry", Entry)
    out = pub.verify_publication(env, _rekor_record(env), Root(), online=False)
    assert out["inclusion"].startswith("invalid: ValueError") and out["ok"] is False
