#!/usr/bin/env python3
"""Run the bounded property/fuzz campaign and preserve replay artifacts."""

from __future__ import annotations

import argparse
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.property_fuzz import (  # noqa: E402
    DEFAULT_CASES,
    DEFAULT_DEADLINE_SECONDS,
    DEFAULT_MAX_SIZE,
    DEFAULT_MAX_STEPS,
    DEFAULT_SEED,
    CampaignConfig,
    run_campaign,
)


def _seed(value: str) -> int:
    try:
        return int(value.replace("_", ""), 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "seed must be an integer such as 1234 or 0xA17A2026"
        ) from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--seed",
        type=_seed,
        default=_seed(os.environ.get("AUTHLAB_FUZZ_SEED", hex(DEFAULT_SEED))),
    )
    parser.add_argument("--cases", type=int, default=DEFAULT_CASES)
    parser.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE)
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    parser.add_argument(
        "--deadline-seconds",
        type=float,
        default=DEFAULT_DEADLINE_SECONDS,
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=ROOT / ".tmp" / "property-fuzz",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = CampaignConfig(
        seed=args.seed,
        cases=args.cases,
        max_size=args.max_size,
        max_steps=args.max_steps,
        deadline_seconds=args.deadline_seconds,
    )
    try:
        report = run_campaign(config, args.output)
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    total = sum(report.cases_run.values())
    print(
        f"Property/fuzz campaign: seed={config.seed}, "
        f"cases={total}, elapsed={report.elapsed_seconds:.3f}s"
    )
    print(f"Artifacts: {args.output}")
    if report.success:
        print("ALL PROPERTIES HOLD — no counterexamples.")
        return 0
    for counterexample in report.counterexamples:
        print(
            f"FAIL {counterexample.property} seed={counterexample.property_seed} "
            f"case={counterexample.case_index}: {counterexample.error}",
            file=sys.stderr,
        )
        print(
            f"minimized={counterexample.minimized!r}",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
