"""The SDK checker never reports CLEAN when it could not actually read the file (cold-audit gap G06)."""
import importlib.util, io, json, pathlib, sys, types, urllib.error
import pytest

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("sdkb", HERE / "agents" / "rapp_sdk_builder_agent.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
cls = next(v for v in vars(mod).values() if isinstance(v, type) and hasattr(v, "_check"))


def run(monkeypatch, behaviour):
    monkeypatch.setattr(mod, "_fetch", behaviour)
    return json.loads(cls.__new__(cls)._check({"repo": "o/r"}))


def raiser(exc):
    def f(*a, **k):
        raise exc
    return f


def test_404_is_clean(monkeypatch):
    assert run(monkeypatch, raiser(urllib.error.HTTPError("u", 404, "nf", {}, io.BytesIO())))["verdict"] == "CLEAN"


@pytest.mark.parametrize("exc", [urllib.error.HTTPError("u", 500, "x", {}, io.BytesIO()),
                                 urllib.error.URLError("offline"), TimeoutError()])
def test_unreadable_is_unknown(monkeypatch, exc):
    assert run(monkeypatch, raiser(exc))["verdict"] == "UNKNOWN"


@pytest.mark.parametrize("body", [b"{not json", b"[1,2]"])
def test_malformed_is_drift(monkeypatch, body):
    assert run(monkeypatch, lambda *a, **k: body)["verdict"] == "DRIFT"
