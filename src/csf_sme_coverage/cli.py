from __future__ import annotations

import argparse
import sys
import time
from typing import Callable, List, Tuple

from . import bridge, filter as flt, score, irish_overlay, visualise, report

# Ordered pipeline registry: (phase-key, human-name, main-function)
PHASES: List[Tuple[str, str, Callable[[], None]]] = [
    ("bridge",         "Phase 2 - CSF -> 800-53 -> ATT&CK bridge",         bridge.main),
    ("filter",         "Phase 4 - SME technique filter",                   flt.main),
    ("score",          "Phase 5 - Coverage metrics",                       score.main),
    ("irish_overlay",  "Phase 5.5 - Irish overlay + ENISA corroboration",  irish_overlay.main),
    ("visualise",      "Phase 6 - Figures",                                visualise.main),
    ("report",         "Phase 7 - Markdown findings summary",              report.main),
]


def _banner(title: str, width: int = 78) -> None:
    print()
    print("#" * width)
    print(f"# {title}")
    print("#" * width)


def _run_phase(phase_key: str, phase_title: str, phase_fn: Callable[[], None]) -> float:
    _banner(phase_title)
    t0 = time.time()
    phase_fn()
    dt = time.time() - t0
    print(f"\n  [{phase_key}] completed in {dt:.1f}s")
    return dt


def _list_phases() -> None:
    print("\nAvailable pipeline phases:\n")
    for key, title, _ in PHASES:
        print(f"  {key:<15}  {title}")
    print("\nRun the whole pipeline with no arguments:  python -m csf_sme_coverage.cli")
    print("Run a single phase:                        python -m csf_sme_coverage.cli <phase>")
    print("Run from a phase onward:                   python -m csf_sme_coverage.cli --from <phase>")


def main(argv: List[str] = None) -> int:
    argv = argv or sys.argv[1:]
    parser = argparse.ArgumentParser(
        prog="csf-sme-coverage",
        description="CSF 2.0 SME threat-informed effectiveness pipeline",
    )
    parser.add_argument("phase", nargs="?", default=None,
                        help="single phase to run; omit to run all phases in order")
    parser.add_argument("--from", dest="from_phase", default=None,
                        help="run from this phase to the end")
    parser.add_argument("--list", action="store_true",
                        help="list available phases and exit")
    args = parser.parse_args(argv)

    if args.list:
        _list_phases()
        return 0

    phase_keys = [p[0] for p in PHASES]

    # Determine which phases to run
    if args.phase and args.from_phase:
        print("[cli] use either `phase` or `--from`, not both", file=sys.stderr)
        return 2

    if args.phase:
        if args.phase not in phase_keys:
            print(f"[cli] unknown phase '{args.phase}'. use --list to see options.",
                  file=sys.stderr)
            return 2
        selected = [p for p in PHASES if p[0] == args.phase]
    elif args.from_phase:
        if args.from_phase not in phase_keys:
            print(f"[cli] unknown phase '{args.from_phase}'. use --list to see options.",
                  file=sys.stderr)
            return 2
        start_idx = phase_keys.index(args.from_phase)
        selected = PHASES[start_idx:]
    else:
        selected = PHASES

    _banner("csf-sme-coverage pipeline start")
    print(f"  Phases to run: {', '.join(p[0] for p in selected)}")

    t_total = time.time()
    timings: List[Tuple[str, float]] = []
    try:
        for key, title, fn in selected:
            dt = _run_phase(key, title, fn)
            timings.append((key, dt))
    except SystemExit as e:
        # A phase called sys.exit()
        print(f"\n[cli] pipeline halted (SystemExit {e.code})", file=sys.stderr)
        return int(e.code or 1)
    except Exception as e:
        print(f"\n[cli] pipeline failed with {type(e).__name__}: {e}", file=sys.stderr)
        raise

    total_dt = time.time() - t_total

    _banner("csf-sme-coverage pipeline complete")
    print(f"  {'phase':<15}  {'time (s)':>10}")
    print(f"  {'-' * 15}  {'-' * 10}")
    for key, dt in timings:
        print(f"  {key:<15}  {dt:>10.1f}")
    print(f"  {'-' * 15}  {'-' * 10}")
    print(f"  {'total':<15}  {total_dt:>10.1f}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
