"""Deterministic, dependency-free property and protocol-state fuzzing.

The campaign is intentionally small enough for every CI run. Inputs and total
runtime are bounded, every property receives a derived seed, and a failure is
delta-minimized before it is written to the artifact directory.
"""

from __future__ import annotations

import json
import platform
import random
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from authlab.crypto.rsa import RSAPublicKey, generate_rsa_keypair
from authlab.directory.scim import SCIMError, SCIMServer
from authlab.jose import HS256, JOSEError, JWS
from authlab.oauth import (
    AuthorizationServer,
    Client,
    InvalidRequest,
    OAuthClient,
    OAuthError,
    User,
    pkce,
)
from authlab.saml import XMLSignatureError, verify_signature
from authlab.util.clock import FrozenClock

DEFAULT_SEED = 0xA17A_2026
DEFAULT_CASES = 128
DEFAULT_MAX_SIZE = 256
DEFAULT_MAX_STEPS = 24
DEFAULT_DEADLINE_SECONDS = 30.0
MAX_CASE_SECONDS = 0.5

_FUZZ_SIGNING_KEY = generate_rsa_keypair(512)
_DUMMY_XML_KEY = RSAPublicKey(n=3, e=65_537)


@dataclass(frozen=True)
class CampaignConfig:
    seed: int = DEFAULT_SEED
    cases: int = DEFAULT_CASES
    max_size: int = DEFAULT_MAX_SIZE
    max_steps: int = DEFAULT_MAX_STEPS
    deadline_seconds: float = DEFAULT_DEADLINE_SECONDS

    def validate(self) -> None:
        if not 1 <= self.cases <= 5_000:
            raise ValueError("cases must be between 1 and 5000")
        if not 1 <= self.max_size <= 4_096:
            raise ValueError("max_size must be between 1 and 4096 bytes")
        if not 1 <= self.max_steps <= 100:
            raise ValueError("max_steps must be between 1 and 100")
        if not 1.0 <= self.deadline_seconds <= 120.0:
            raise ValueError("deadline_seconds must be between 1 and 120")


@dataclass(frozen=True)
class Counterexample:
    property: str
    property_seed: int
    case_index: int
    error: str
    original: Any
    minimized: Any


@dataclass(frozen=True)
class CampaignReport:
    success: bool
    elapsed_seconds: float
    cases_run: dict[str, int]
    property_seeds: dict[str, int]
    counterexamples: list[Counterexample]


@dataclass(frozen=True)
class PropertySpec:
    name: str
    generate: Callable[[random.Random, CampaignConfig], Any]
    check: Callable[[Any], None]
    minimize: Callable[[Any, Callable[[Any], bool]], Any]


def _bounded_text(rng: random.Random, limit: int, alphabet: str) -> str:
    size = rng.randint(0, limit)
    return "".join(rng.choice(alphabet) for _ in range(size))


def _malformed_compact_token(
        rng: random.Random,
        config: CampaignConfig,
) -> str:
    text = _bounded_text(
        rng,
        config.max_size,
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
    )
    templates = (
        text,
        f"{text}.{text}",
        f"{text}.{text}.{text}.{text}",
        f".{text}.{text}",
        f"{text}..{text}",
        f"@@@.{text}.{text}",
        f"e30.{text}.",
        f"bm90LWpzb24.{text}.{text}",
    )
    value = rng.choice(templates)
    return value[: config.max_size]


def _check_malformed_compact_token(value: str) -> None:
    try:
        JWS.verify(value, b"fixture-key", [HS256])
    except JOSEError:
        return
    except Exception as exc:
        raise AssertionError(
            f"compact-token parser leaked {type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError("malformed compact token was accepted")


def _malformed_xml(rng: random.Random, config: CampaignConfig) -> str:
    text = _bounded_text(rng, max(1, config.max_size // 2), "abcXYZ0123 <>&/=\"'")
    templates = (
        "",
        " " * max(1, len(text)),
        "<",
        f"<root>{text}",
        f"<root><child>{text}</root>",
        f"</{text or 'root'}>",
        f"<root a=\"1\" a=\"2\">{text}</root>",
        f"<!DOCTYPE root [<!ENTITY x \"{text}\">]><root>&x;</root>",
        f"<root>{text}</root>",
    )
    value = rng.choice(templates)
    return value[: config.max_size]


def _check_malformed_xml(value: str) -> None:
    try:
        verify_signature(value, _DUMMY_XML_KEY)
    except XMLSignatureError:
        return
    except Exception as exc:
        raise AssertionError(
            f"XML verifier leaked {type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError("malformed or unsigned XML was accepted")


def _malformed_scim_filter(
        rng: random.Random,
        config: CampaignConfig,
) -> str:
    value = _bounded_text(
        rng,
        max(1, config.max_size // 4),
        "abcdefghijklmnopqrstuvwxyz0123456789",
    )
    quoted = json.dumps(value)
    templates = (
        " " * max(1, len(value)),
        "(" * max(1, min(len(value), 8)),
        "userName",
        "userName eq",
        f"userName eq {quoted} and",
        f"(userName eq {quoted}",
        f"userName unsupported {quoted}",
        f"userName eq {quoted} trailing",
    )
    return rng.choice(templates)[: config.max_size]


def _check_malformed_scim_filter(value: str) -> None:
    server = SCIMServer()
    server.create_user({"userName": "alice"})
    try:
        server.list_users(value)
    except SCIMError:
        return
    except Exception as exc:
        raise AssertionError(
            f"SCIM filter parser leaked {type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError("malformed SCIM filter was accepted")


_CLIENT_OPERATIONS = (
    "begin",
    "valid_callback",
    "wrong_state",
    "missing_code",
    "other_session",
    "authorization_error",
)


def _client_operations(
        rng: random.Random,
        config: CampaignConfig,
) -> list[str]:
    return [
        rng.choice(_CLIENT_OPERATIONS)
        for _ in range(rng.randint(1, config.max_steps))
    ]


def _expect_oauth_rejection(label: str, action: Callable[[], Any]) -> None:
    try:
        action()
    except OAuthError:
        return
    except Exception as exc:
        raise AssertionError(
            f"{label} leaked {type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError(f"{label} unexpectedly succeeded")


def _check_client_operations(operations: Sequence[str]) -> None:
    clock = FrozenClock(1_700_000_000)
    client = OAuthClient(
        client_id="web-app",
        redirect_uri="https://app.auth-lab.local/cb",
        authorization_endpoint="https://as.auth-lab.local/authorize",
        token_endpoint="https://as.auth-lab.local/token",
        issuer="https://as.auth-lab.local",
        clock=clock,
    )
    session_id = "session"
    pending = False
    last_valid_callback: str | None = None

    for operation in operations:
        if operation == "begin":
            client.begin(session_id)
            pending = True
            state = client.pending[session_id].state
            last_valid_callback = (
                f"https://app.auth-lab.local/cb?code=fixture&state={state}"
            )
        elif operation == "valid_callback":
            callback = last_valid_callback or (
                "https://app.auth-lab.local/cb?code=fixture&state=missing"
            )
            if pending:
                result = client.handle_callback(session_id, callback)
                if result.get("code") != "fixture":
                    raise AssertionError("valid callback lost its code binding")
                pending = False
            else:
                _expect_oauth_rejection(
                    "callback before begin or after consumption",
                    lambda: client.handle_callback(session_id, callback),
                )
        elif operation == "wrong_state":
            _expect_oauth_rejection(
                "callback with wrong state",
                lambda: client.handle_callback(
                    session_id,
                    "https://app.auth-lab.local/cb?code=fixture&state=attacker",
                ),
            )
        elif operation == "missing_code":
            state = (
                client.pending[session_id].state
                if pending
                else "missing"
            )
            _expect_oauth_rejection(
                "callback without code",
                lambda: client.handle_callback(
                    session_id,
                    f"https://app.auth-lab.local/cb?state={state}",
                ),
            )
        elif operation == "other_session":
            _expect_oauth_rejection(
                "callback bound to another session",
                lambda: client.handle_callback(
                    "attacker-session",
                    last_valid_callback
                    or "https://app.auth-lab.local/cb?code=x&state=y",
                ),
            )
        elif operation == "authorization_error":
            state = (
                client.pending[session_id].state
                if pending
                else "missing"
            )
            _expect_oauth_rejection(
                "authorization error callback",
                lambda: client.handle_callback(
                    session_id,
                    f"https://app.auth-lab.local/cb?error=access_denied&state={state}",
                ),
            )
            if pending:
                pending = False
        else:
            raise AssertionError(f"generator emitted unknown operation: {operation}")

    if last_valid_callback is not None and not pending:
        _expect_oauth_rejection(
            "consumed callback replay",
            lambda: client.handle_callback(session_id, last_valid_callback),
        )


_TOKEN_OPERATIONS = (
    "redeem_code",
    "refresh_original",
    "refresh_current",
    "replay_last_used_refresh",
    "missing_code",
    "unknown_grant",
)


def _token_operations(
        rng: random.Random,
        config: CampaignConfig,
) -> list[str]:
    return [
        rng.choice(_TOKEN_OPERATIONS)
        for _ in range(rng.randint(1, config.max_steps))
    ]


def _new_authorization_server() -> tuple[AuthorizationServer, dict[str, str]]:
    clock = FrozenClock(1_700_000_000)
    server = AuthorizationServer(
        issuer="https://as.auth-lab.local",
        clock=clock,
        signing_key=_FUZZ_SIGNING_KEY,
    )
    server.register_client(
        Client(
            client_id="web-app",
            redirect_uris=["https://app.auth-lab.local/cb"],
            scopes=["openid", "orders:read"],
            token_endpoint_auth_method="none",
        )
    )
    server.register_user(
        User(subject="u-alice", username="alice", password_hash="fixture")
    )
    verifier, challenge = pkce.generate_pair()
    validated = server.validate_authorization_request(
        {
            "client_id": "web-app",
            "redirect_uri": "https://app.auth-lab.local/cb",
            "response_type": "code",
            "scope": "openid orders:read",
            "state": "state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    code = server.issue_authorization_code(validated, "u-alice")
    return server, {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://app.auth-lab.local/cb",
        "client_id": "web-app",
        "code_verifier": verifier,
    }


def _refresh_request(token: str) -> dict[str, str]:
    return {
        "grant_type": "refresh_token",
        "refresh_token": token,
        "client_id": "web-app",
    }


def _check_token_operations(operations: Sequence[str]) -> None:
    server, code_request = _new_authorization_server()
    code_used = False
    family_revoked = False
    original_refresh: str | None = None
    current_refresh: str | None = None
    used_refreshes: list[str] = []

    for operation in operations:
        if operation == "redeem_code":
            if not code_used:
                tokens = server.token(code_request)
                code_used = True
                original_refresh = tokens["refresh_token"]
                current_refresh = original_refresh
            else:
                _expect_oauth_rejection(
                    "authorization-code replay",
                    lambda: server.token(code_request),
                )
                family_revoked = True
        elif operation == "refresh_original":
            token = original_refresh or "unknown-refresh"
            valid = (
                original_refresh is not None
                and token not in used_refreshes
                and not family_revoked
            )
            if valid:
                tokens = server.token(_refresh_request(token))
                used_refreshes.append(token)
                current_refresh = tokens["refresh_token"]
            else:
                _expect_oauth_rejection(
                    "refresh before issue or original replay",
                    lambda token=token: server.token(_refresh_request(token)),
                )
                if original_refresh is not None and token in used_refreshes:
                    family_revoked = True
        elif operation == "refresh_current":
            token = current_refresh or "unknown-current-refresh"
            valid = (
                current_refresh is not None
                and token not in used_refreshes
                and not family_revoked
            )
            if valid:
                tokens = server.token(_refresh_request(token))
                used_refreshes.append(token)
                current_refresh = tokens["refresh_token"]
            else:
                _expect_oauth_rejection(
                    "invalid current refresh transition",
                    lambda token=token: server.token(_refresh_request(token)),
                )
        elif operation == "replay_last_used_refresh":
            token = used_refreshes[-1] if used_refreshes else "never-issued"
            _expect_oauth_rejection(
                "used refresh replay",
                lambda token=token: server.token(_refresh_request(token)),
            )
            if used_refreshes:
                family_revoked = True
        elif operation == "missing_code":
            _expect_oauth_rejection(
                "authorization-code grant without code",
                lambda: server.token(
                    {
                        "grant_type": "authorization_code",
                        "client_id": "web-app",
                    }
                ),
            )
        elif operation == "unknown_grant":
            _expect_oauth_rejection(
                "unknown grant transition",
                lambda: server.token(
                    {"grant_type": "generated-invalid", "client_id": "web-app"}
                ),
            )
        else:
            raise AssertionError(f"generator emitted unknown operation: {operation}")

    replay_material = [code_request]
    replay_material.extend(_refresh_request(token) for token in used_refreshes)
    for request in reversed(replay_material):
        if request is code_request and not code_used:
            continue
        _expect_oauth_rejection(
            "arbitrarily ordered replay",
            lambda request=request: server.token(request),
        )


def minimize_text(value: str, still_fails: Callable[[str], bool]) -> str:
    return _ddmin(value, still_fails, lambda item: item)


def minimize_sequence(
        value: Sequence[str],
        still_fails: Callable[[list[str]], bool],
) -> list[str]:
    return _ddmin(list(value), still_fails, list)


def _ddmin(
        value: Any,
        still_fails: Callable[[Any], bool],
        convert: Callable[[Any], Any],
) -> Any:
    current = value
    granularity = 2
    while len(current) >= 2:
        chunk_size = max(1, (len(current) + granularity - 1) // granularity)
        reduced = False
        for start in range(0, len(current), chunk_size):
            candidate = convert(current[:start] + current[start + chunk_size :])
            if still_fails(candidate):
                current = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if not reduced:
            if granularity >= len(current):
                break
            granularity = min(len(current), granularity * 2)
    return current


PROPERTY_SPECS = (
    PropertySpec(
        "malformed_compact_token",
        _malformed_compact_token,
        _check_malformed_compact_token,
        minimize_text,
    ),
    PropertySpec(
        "malformed_or_unsigned_xml",
        _malformed_xml,
        _check_malformed_xml,
        minimize_text,
    ),
    PropertySpec(
        "malformed_scim_filter",
        _malformed_scim_filter,
        _check_malformed_scim_filter,
        minimize_text,
    ),
    PropertySpec(
        "oauth_client_state_machine",
        _client_operations,
        _check_client_operations,
        minimize_sequence,
    ),
    PropertySpec(
        "oauth_token_replay_ordering",
        _token_operations,
        _check_token_operations,
        minimize_sequence,
    ),
)


def run_campaign(config: CampaignConfig, output_dir: Path) -> CampaignReport:
    config.validate()
    output_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    deadline = started + config.deadline_seconds
    campaign_rng = random.Random(config.seed)
    cases_run: dict[str, int] = {}
    property_seeds: dict[str, int] = {}
    counterexamples: list[Counterexample] = []

    (output_dir / "seed.txt").write_text(f"{config.seed}\n", encoding="utf-8")

    for spec in PROPERTY_SPECS:
        property_seed = campaign_rng.getrandbits(64)
        property_seeds[spec.name] = property_seed
        rng = random.Random(property_seed)
        cases_run[spec.name] = 0
        for case_index in range(config.cases):
            if time.monotonic() >= deadline:
                counterexamples.append(
                    Counterexample(
                        property=spec.name,
                        property_seed=property_seed,
                        case_index=case_index,
                        error="campaign deadline exceeded",
                        original=None,
                        minimized=None,
                    )
                )
                break
            value = spec.generate(rng, config)
            case_started = time.monotonic()
            try:
                spec.check(value)
                elapsed = time.monotonic() - case_started
                if elapsed > MAX_CASE_SECONDS:
                    raise AssertionError(
                        f"case exceeded {MAX_CASE_SECONDS:.3f}s: {elapsed:.3f}s"
                    )
            except AssertionError as exc:
                def still_fails(candidate: Any) -> bool:
                    try:
                        spec.check(candidate)
                    except AssertionError:
                        return True
                    return False

                minimized = spec.minimize(value, still_fails)
                counterexamples.append(
                    Counterexample(
                        property=spec.name,
                        property_seed=property_seed,
                        case_index=case_index,
                        error=str(exc),
                        original=value,
                        minimized=minimized,
                    )
                )
                cases_run[spec.name] += 1
                break
            cases_run[spec.name] += 1

    elapsed_seconds = time.monotonic() - started
    report = CampaignReport(
        success=not counterexamples,
        elapsed_seconds=elapsed_seconds,
        cases_run=cases_run,
        property_seeds=property_seeds,
        counterexamples=counterexamples,
    )
    (output_dir / "counterexamples.json").write_text(
        json.dumps(
            [asdict(item) for item in counterexamples],
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (output_dir / "summary.json").write_text(
        json.dumps(
            {
                "success": report.success,
                "elapsed_seconds": round(report.elapsed_seconds, 6),
                "configuration": asdict(config),
                "cases_run": report.cases_run,
                "property_seeds": report.property_seeds,
                "python": platform.python_version(),
                "counterexample_count": len(report.counterexamples),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return report
