#!/usr/bin/env python3
"""Compare a candidate /chat implementation with the pinned Grail."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from scenarios import MODEL, SCENARIOS, Scenario  # noqa: E402


PIN_PATH = HERE / "kernel.json"
REPORT_PATH = HERE / "report.json"
PIN_KEYS = {"repo", "commit", "path", "blob", "version"}
DEFAULT_GRAIL_PYTHON = Path("~/.airaptr/venv/bin/python").expanduser()


class ConformanceError(RuntimeError):
    pass


@dataclass(frozen=True)
class ModuleContext:
    fake_model_url: str
    fake_token_url: str
    model: str
    agents_dir: Path
    work_dir: Path


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def load_pin() -> dict:
    pin = json.loads(PIN_PATH.read_text(encoding="utf-8"))
    if set(pin) != PIN_KEYS or not all(isinstance(pin[key], str) for key in PIN_KEYS):
        raise ConformanceError(f"{PIN_PATH} must contain exactly {sorted(PIN_KEYS)}")
    return pin


def resolve_grail_dir(value: str, pin: Optional[dict] = None) -> Path:
    requested = Path(value).expanduser().resolve()
    candidates = [requested]
    if pin is not None:
        candidates.append(requested / Path(pin["path"]).parent)
    candidates.append(requested / "rapp_brainstem")
    for candidate in candidates:
        if (candidate / "brainstem.py").is_file():
            return candidate
    raise ConformanceError(f"no brainstem.py found under {requested}")


def verify_oracle(value: str, pin: dict) -> Tuple[Path, str]:
    grail = resolve_grail_dir(value, pin)
    source = (grail / "brainstem.py").read_bytes()
    blob = git_blob(source)
    if blob != pin["blob"]:
        raise ConformanceError(
            f"oracle brainstem.py blob {blob} != pinned {pin['blob']}; refusing mismatch"
        )
    version_path = grail / "VERSION"
    if not version_path.is_file():
        raise ConformanceError(f"oracle VERSION is missing at {version_path}")
    version = version_path.read_text(encoding="utf-8").strip()
    if version != pin["version"]:
        raise ConformanceError(
            f"oracle VERSION {version!r} != pinned {pin['version']!r}"
        )
    return grail, blob


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_url(url: str, timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2).close()
            return True
        except urllib.error.HTTPError:
            return True
        except OSError:
            time.sleep(0.2)
    return False


def decode_response(code: int, raw: Any) -> Tuple[int, dict]:
    if isinstance(raw, str):
        raw = raw.encode()
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError):
        decoded = {"_raw": raw[:120].decode(errors="replace")}
    if not isinstance(decoded, dict):
        decoded = {"_json": decoded}
    return code, decoded


def call_http(base_url: str, scenario: Scenario) -> Tuple[int, dict]:
    data = None
    if scenario.body is not None:
        data = (
            scenario.body
            if isinstance(scenario.body, bytes)
            else json.dumps(scenario.body).encode()
        )
    request = urllib.request.Request(
        base_url.rstrip("/") + scenario.path,
        data=data,
        method=scenario.method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return decode_response(response.status, response.read())
    except urllib.error.HTTPError as error:
        return decode_response(error.code, error.read())


def contract_view(
    scenario: Scenario,
    code: int,
    body: dict,
    *,
    compare_error_text: bool,
) -> dict:
    if scenario.name == "health agents":
        agents = body.get("agents", [])
        return {
            "code": code,
            "status": body.get("status"),
            "agents": sorted(agents) if isinstance(agents, list) else agents,
        }
    if scenario.name == "version":
        return {
            "code": code,
            "has_version": isinstance(body.get("version"), str),
        }
    if scenario.name == "not found":
        return {"code": code}
    if code == 200:
        return {
            "code": code,
            "keys": sorted(body),
            "response": body.get("response"),
            "session_id": body.get("session_id"),
            "agent_logs": body.get("agent_logs"),
            "voice_mode": body.get("voice_mode"),
            "model": body.get("model"),
            "requested_model": body.get("requested_model"),
            **(
                {"voice_response": body.get("voice_response")}
                if "voice_response" in body
                else {}
            ),
        }
    view = {"code": code, "keys": sorted(body)}
    if compare_error_text:
        view["error"] = body.get("error")
    return view


def prepare_grail(source: Path, target: Path) -> Path:
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns(
            "agents",
            ".brainstem_model",
            ".copilot_*",
            ".env",
            ".git",
            ".venv",
            "__pycache__",
            "tests",
        ),
    )
    agents = target / "agents"
    agents.mkdir()
    basic_agent = source / "agents" / "basic_agent.py"
    if not basic_agent.is_file():
        raise ConformanceError(f"Grail basic agent is missing at {basic_agent}")
    shutil.copy2(basic_agent, agents / basic_agent.name)
    for fixture in (HERE / "agents").glob("*_agent.py"):
        shutil.copy2(fixture, agents / fixture.name)
    return target


def read_log(path: Path) -> str:
    try:
        return path.read_text(errors="replace")[-4000:]
    except OSError:
        return "(log unavailable)"


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def grail_environment(
    home: Path,
    *,
    expected_blob: Optional[str],
) -> dict:
    home.mkdir(parents=True, exist_ok=True)
    environment = dict(
        os.environ,
        HOME=str(home),
        GITHUB_TOKEN="ghu_fake",
        GITHUB_MODEL=MODEL,
        VOICE_MODE="false",
        GRAIL_MODEL=MODEL,
    )
    if expected_blob is None:
        environment.pop("GRAIL_BLOB", None)
    else:
        environment["GRAIL_BLOB"] = expected_blob
    return environment


def start_grail(
    source: Path,
    target: Path,
    *,
    port: int,
    fake_port: int,
    python: str,
    expected_blob: Optional[str],
    log_path: Path,
) -> Tuple[subprocess.Popen, Any]:
    grail = prepare_grail(source, target)
    handle = log_path.open("w")
    process = subprocess.Popen(
        [
            python,
            str(HERE / "run_grail.py"),
            str(grail),
            str(port),
            str(fake_port),
        ],
        env=grail_environment(
            target.parent / f"{target.name}-home",
            expected_blob=expected_blob,
        ),
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    if not wait_for_url(f"http://127.0.0.1:{port}/health"):
        stop_process(process)
        handle.close()
        raise ConformanceError(
            f"Grail did not start from {source}:\n{read_log(log_path)}"
        )
    return process, handle


def normalize_module_result(result: Any) -> Tuple[int, dict]:
    if isinstance(result, tuple) and len(result) == 2:
        code, body = result
        if not isinstance(code, int):
            raise ConformanceError("module candidate status must be an integer")
        if isinstance(body, dict):
            return code, body
        if isinstance(body, str):
            body = body.encode()
        if isinstance(body, bytes):
            return decode_response(code, body)
        raise ConformanceError("module candidate body must be a dict, str, or bytes")
    if hasattr(result, "status_code") and hasattr(result, "get_body"):
        return decode_response(result.status_code or 200, result.get_body())
    raise ConformanceError(
        "module candidate must return (status, body) or an HttpResponse-like object"
    )


def load_module_candidate(
    value: str,
    context: ModuleContext,
) -> Callable[[Scenario], Tuple[int, dict]]:
    module_name, separator, factory_name = value.rpartition(":")
    if not separator or not module_name or not factory_name:
        raise ConformanceError(
            "module candidate must be module:<python-import-path>:<factory>"
        )
    module = importlib.import_module(module_name)
    factory = getattr(module, factory_name, None)
    if not callable(factory):
        raise ConformanceError(f"{module_name}.{factory_name} is not callable")
    candidate = factory(context)
    if hasattr(candidate, "call") and callable(candidate.call):
        invoke = candidate.call
    elif callable(candidate):
        invoke = candidate
    else:
        raise ConformanceError(
            "module factory must return a callable or an object with call()"
        )

    def call(scenario: Scenario) -> Tuple[int, dict]:
        return normalize_module_result(
            invoke(scenario.method, scenario.path, scenario.body)
        )

    return call


def load_allow_list(path: Optional[str]) -> Dict[str, str]:
    if path is None:
        return {}
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise ConformanceError("allow file must be a JSON list")
    known = {scenario.name for scenario in SCENARIOS}
    allowed = {}
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"scenario", "reason"}:
            raise ConformanceError(
                "each allow entry must contain exactly scenario and reason"
            )
        scenario = entry["scenario"]
        reason = entry["reason"]
        if (
            not isinstance(scenario, str)
            or scenario not in known
            or not isinstance(reason, str)
            or not reason.strip()
        ):
            raise ConformanceError(
                "allow entries require a known scenario and a non-empty reason"
            )
        if scenario in allowed:
            raise ConformanceError(f"duplicate allow entry for {scenario}")
        allowed[scenario] = reason.strip()
    return allowed


def write_report(report: dict) -> None:
    REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> int:
    pin = load_pin()
    if not args.grail:
        raise ConformanceError("set GRAIL_DIR or pass --grail <dir>")
    oracle_dir, oracle_blob = verify_oracle(args.grail, pin)
    allow = load_allow_list(args.allow_file)

    if args.candidate.startswith("grail:"):
        mode = "grail"
        candidate_value = args.candidate[len("grail:") :]
    elif args.candidate.startswith("http:"):
        mode = "http"
        candidate_value = args.candidate[len("http:") :]
    elif args.candidate.startswith("module:"):
        mode = "module"
        candidate_value = args.candidate[len("module:") :]
    else:
        raise ConformanceError("candidate must start with grail:, http:, or module:")
    if not candidate_value:
        raise ConformanceError("candidate value is empty")
    if args.same_version and mode != "http":
        raise ConformanceError("--same-version is only valid with an http: candidate")

    scenarios = [
        scenario
        for scenario in SCENARIOS
        if mode != "http" or not scenario.needs_model
    ]
    grail_python = os.environ.get(
        "GRAIL_PYTHON",
        str(
            DEFAULT_GRAIL_PYTHON
            if DEFAULT_GRAIL_PYTHON.exists()
            else Path(sys.executable)
        ),
    )
    if not Path(grail_python).is_file():
        raise ConformanceError(f"Grail Python interpreter not found: {grail_python}")

    work = Path(tempfile.mkdtemp(prefix="grail-conformance-"))
    processes = []
    handles = []
    try:
        fake_port = free_port()
        fake_log = work / "fake.log"
        fake_handle = fake_log.open("w")
        handles.append(fake_handle)
        fake_process = subprocess.Popen(
            [sys.executable, str(HERE / "fake_model.py"), str(fake_port)],
            stdout=fake_handle,
            stderr=subprocess.STDOUT,
        )
        processes.append(fake_process)
        if not wait_for_url(f"http://127.0.0.1:{fake_port}/models", timeout=10):
            raise ConformanceError(
                "fake model did not start:\n" + read_log(fake_log)
            )

        oracle_port = free_port()
        oracle_process, oracle_handle = start_grail(
            oracle_dir,
            work / "oracle",
            port=oracle_port,
            fake_port=fake_port,
            python=grail_python,
            expected_blob=oracle_blob,
            log_path=work / "oracle.log",
        )
        processes.append(oracle_process)
        handles.append(oracle_handle)
        oracle_url = f"http://127.0.0.1:{oracle_port}"

        if mode == "grail":
            candidate_dir = resolve_grail_dir(candidate_value)
            candidate_port = free_port()
            candidate_process, candidate_handle = start_grail(
                candidate_dir,
                work / "candidate",
                port=candidate_port,
                fake_port=fake_port,
                python=grail_python,
                expected_blob=None,
                log_path=work / "candidate.log",
            )
            processes.append(candidate_process)
            handles.append(candidate_handle)
            candidate_call = lambda scenario: call_http(
                f"http://127.0.0.1:{candidate_port}", scenario
            )
        elif mode == "http":
            candidate_call = lambda scenario: call_http(candidate_value, scenario)
        else:
            context = ModuleContext(
                fake_model_url=f"http://127.0.0.1:{fake_port}/v1",
                fake_token_url=f"http://127.0.0.1:{fake_port}/token",
                model=MODEL,
                agents_dir=HERE / "agents",
                work_dir=work / "module",
            )
            context.work_dir.mkdir()
            candidate_call = load_module_candidate(candidate_value, context)

        if allow:
            print("Allow list:")
            for name, reason in allow.items():
                print(f"  {name}: {reason}")

        rows = []
        identical = 0
        allowed_differences = 0
        unallowed_differences = 0
        compare_error_text = mode != "http" or args.same_version
        for scenario in scenarios:
            oracle = contract_view(
                scenario,
                *call_http(oracle_url, scenario),
                compare_error_text=True,
            )
            candidate = contract_view(
                scenario,
                *candidate_call(scenario),
                compare_error_text=compare_error_text,
            )
            if not compare_error_text and oracle["code"] != 200:
                oracle.pop("error", None)
            same = oracle == candidate
            allowed = not same and scenario.name in allow
            identical += int(same)
            allowed_differences += int(allowed)
            unallowed_differences += int(not same and not allowed)
            rows.append(
                {
                    "scenario": scenario.name,
                    "needs_model": scenario.needs_model,
                    "same": same,
                    "allowed": allowed,
                    "reason": allow.get(scenario.name) if allowed else None,
                    "oracle": oracle,
                    "candidate": candidate,
                }
            )
            if same:
                print(f"  same   {scenario.name}")
            elif allowed:
                print(
                    f"  ALLOW  {scenario.name}: {allow[scenario.name]}"
                    f"\n          oracle: {oracle}"
                    f"\n       candidate: {candidate}"
                )
            else:
                print(
                    f"  DIFF   {scenario.name}"
                    f"\n          oracle: {oracle}"
                    f"\n       candidate: {candidate}"
                )

        report = {
            "oracle": {
                "directory": str(oracle_dir),
                "kernel": pin,
                "blob": oracle_blob,
            },
            "candidate": {"mode": mode, "value": candidate_value},
            "same_version": args.same_version,
            "allow": [
                {"scenario": name, "reason": reason}
                for name, reason in allow.items()
            ],
            "identical": identical,
            "allowed_differences": allowed_differences,
            "unallowed_differences": unallowed_differences,
            "total": len(scenarios),
            "scenarios": rows,
        }
        write_report(report)
        if allowed_differences:
            print(
                f"\n{identical} identical, {allowed_differences} allowed, "
                f"{len(scenarios)} scenarios compared"
            )
        else:
            print(f"\n{identical} of {len(scenarios)} scenarios identical")
        return 1 if unallowed_differences else 0
    finally:
        for process in reversed(processes):
            stop_process(process)
        for handle in handles:
            handle.close()
        shutil.rmtree(work, ignore_errors=True)


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare a candidate with the pinned Grail /chat behavior."
    )
    parser.add_argument(
        "--candidate",
        required=True,
        help="grail:<dir>, http:<base-url>, or module:<import-path>:<factory>",
    )
    parser.add_argument(
        "--grail",
        default=os.environ.get("GRAIL_DIR"),
        help="pinned oracle Grail directory (default: GRAIL_DIR)",
    )
    parser.add_argument(
        "--allow",
        dest="allow_file",
        help="JSON list of allowed scenario differences and reasons",
    )
    parser.add_argument(
        "--same-version",
        action="store_true",
        help="for http: candidates, compare exact error text too",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        return run(args)
    except (ConformanceError, ImportError, AttributeError, OSError, ValueError) as error:
        write_report(
            {
                "candidate": args.candidate,
                "error": str(error),
            }
        )
        print(f"conformance failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
