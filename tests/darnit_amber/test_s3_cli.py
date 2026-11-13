"""``--store s3`` from the CLI side: listing bundles among output blobs, and a missing boto3 reported in one line.
The store itself is tested against moto in ``test_s3_store``."""

import pytest


def test_s3_list_bundles_ignores_output_blobs():
    pytest.importorskip("boto3")
    from darnit_amber.s3_store import S3AttestationStore

    pages = [
        {
            "Contents": [
                {"Key": "amber/runs/abc.intoto.json"},
                {"Key": "amber/runs/abc/outputs/result.txt"},
                {"Key": "amber/runs/notes.md"},
            ]
        }
    ]

    class Paginator:
        def paginate(self, **kw):
            return pages

    class Client:
        def get_paginator(self, _):
            return Paginator()

    store = S3AttestationStore.__new__(S3AttestationStore)
    store._client, store._bucket, store._prefix = Client(), "b", "amber/runs"
    assert store.list_bundles() == ["abc"]


def test_store_s3_without_boto3_is_one_line(monkeypatch, capsys):
    """boto3 is imported by the store's constructor, so a missing boto3 surfaced as a traceback (VM, Nov 12)."""
    import builtins

    from darnit_amber import cli

    real_import = builtins.__import__

    def no_boto3(name, *args, **kwargs):
        if name == "boto3":
            raise ModuleNotFoundError("No module named 'boto3'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_boto3)
    rc = cli.main(["verify", "x", "--store", "s3", "--bucket", "b"])
    out, err = capsys.readouterr()
    assert rc == 1 and "pip install 'darnit-amber[s3]'" in err and "Traceback" not in err
