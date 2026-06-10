#!/usr/bin/env python3
"""Citadel resource allocator.

Detects the REAL host RAM/CPU, then divides the allocatable pool (after
headroom) across services by the weights in ``config/resources.yaml`` and emits
a Helm values overlay:

    scripts/allocate_resources.py            # detect + write the overlay
    scripts/allocate_resources.py --print    # also print the allocation table
    helm template charts/citadel -f charts/citadel/values-resources.generated.yaml

The config may *claim* a budget (e.g. 64Gi) but the allocator caps it at what
the host actually has — you never over-commit a node.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "resources.yaml"
OUT = ROOT / "charts" / "citadel" / "values-resources.generated.yaml"

# Components that map to chart `resources` blocks (compute pool).
COMPUTE = ("api", "processor", "frontend", "elasticsearch", "redis", "minio")
# Stateful components that get a PVC from total.storage.
STATEFUL = ("elasticsearch", "minio", "redis")
# Chart value path for each substrate subchart's resources/persistence
# (bitnami-style keys) vs the first-party components.
_SUBCHART = {"elasticsearch", "redis", "minio"}


def detect_memory_bytes() -> int:
    # Works on Linux + macOS without psutil.
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        pass
    try:
        import subprocess
        return int(subprocess.check_output(["sysctl", "-n", "hw.memsize"]).strip())
    except Exception:
        return 8 * 1024**3  # conservative fallback


def detect_cpu() -> int:
    return os.cpu_count() or 2


def _parse_mem(v) -> int | None:
    """'64Gi'/'512Mi'/bytes-int -> bytes. 'auto'/None -> None."""
    if v is None or str(v).lower() == "auto":
        return None
    s = str(v).strip()
    units = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4,
             "K": 1000, "M": 1000**2, "G": 1000**3, "T": 1000**4}
    for u, mult in units.items():
        if s.endswith(u):
            return int(float(s[:-len(u)]) * mult)
    return int(float(s))


def _mi(b: float) -> str:
    return f"{max(1, round(b / 1024**2))}Mi"


def _gi_str(b: float) -> str:
    return f"{round(b / 1024**3, 1)}Gi"


def allocate(cfg: dict) -> tuple[dict, dict]:
    headroom = cfg.get("headroom_pct", 20) / 100.0
    rratio = cfg.get("requests_ratio", 0.5)
    floors = cfg.get("floors", {})
    fl_mem = floors.get("memory_mi", 128) * 1024**2
    fl_cpu = floors.get("cpu_m", 100)

    host_mem = detect_memory_bytes()
    host_cpu = detect_cpu()
    claim_mem = _parse_mem(cfg.get("total", {}).get("memory"))
    claim_cpu = cfg.get("total", {}).get("cpu")
    claim_cpu = None if str(claim_cpu).lower() == "auto" else (int(claim_cpu) if claim_cpu else None)

    # Admin ceiling: Citadel may use at most this % of the host (it may share
    # the box with other workloads). Caps memory AND cpu before headroom.
    max_pct = cfg.get("max_pct_of_host", 100) / 100.0
    cap_mem = host_mem * max_pct
    cap_cpu = host_cpu * max_pct

    warnings = []
    # Budget = min(host cap, admin %-cap, explicit total claim).
    budget_mem = min(host_mem, cap_mem)
    if claim_mem and claim_mem > host_mem:
        warnings.append(f"config claims {_gi_str(claim_mem)} RAM but host has "
                        f"{_gi_str(host_mem)} — capping at host.")
    elif claim_mem:
        budget_mem = min(budget_mem, claim_mem)
    if max_pct < 1.0:
        warnings.append(f"admin cap: Citadel limited to {int(max_pct*100)}% of host "
                        f"({_gi_str(cap_mem)} RAM / {round(cap_cpu,1)} CPU) before headroom.")

    budget_cpu = min(host_cpu, cap_cpu)
    if claim_cpu and claim_cpu > host_cpu:
        warnings.append(f"config claims {claim_cpu} CPU but host has {host_cpu} — capping.")
    elif claim_cpu:
        budget_cpu = min(budget_cpu, claim_cpu)

    alloc_mem = budget_mem * (1 - headroom)
    alloc_cpu = budget_cpu * (1 - headroom)

    weights = cfg.get("weights", {})
    wsum = sum(weights.get(s, 0) for s in COMPUTE) or 1

    plan = {}
    for svc in COMPUTE:
        w = weights.get(svc, 0)
        mem_lim = max(fl_mem, alloc_mem * w / wsum)
        cpu_lim_m = max(fl_cpu, round(alloc_cpu * 1000 * w / wsum))
        plan[svc] = {
            "requests": {"cpu": f"{int(cpu_lim_m * rratio)}m", "memory": _mi(mem_lim * rratio)},
            "limits": {"cpu": f"{int(cpu_lim_m)}m", "memory": _mi(mem_lim)},
        }

    total_storage = _parse_mem(cfg.get("total", {}).get("storage")) or 100 * 1024**3
    sw = cfg.get("storage_weights", {})
    storage = {svc: _gi_str(total_storage * sw.get(svc, 0) / 100.0) for svc in STATEFUL}

    meta = {
        "host_memory": _gi_str(host_mem), "host_cpu": host_cpu,
        "allocatable_memory": _gi_str(alloc_mem), "allocatable_cpu": round(alloc_cpu, 1),
        "warnings": warnings,
    }
    return plan, {"storage": storage, "meta": meta}


def to_values(plan: dict, extra: dict) -> dict:
    """Render the allocation into the umbrella chart's values layout."""
    storage = extra["storage"]
    values: dict = {
        "_generated_by": "scripts/allocate_resources.py",
        "_host": extra["meta"],
    }
    # First-party components: api/processor/frontend → <svc>.resources
    for svc in ("api", "processor", "frontend"):
        values[svc] = {"resources": plan[svc]}
    # Substrate subcharts (bitnami-style): resources + persistence.size
    values["elasticsearch"] = {
        "master": {"resources": plan["elasticsearch"],
                   "persistence": {"size": storage["elasticsearch"]}},
    }
    values["redis"] = {
        "master": {"resources": plan["redis"],
                   "persistence": {"size": storage["redis"]}},
    }
    values["minio"] = {
        "resources": plan["minio"],
        "persistence": {"size": storage["minio"]},
    }
    return values


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Allocate cluster resources from a global config.")
    ap.add_argument("--config", default=str(CONFIG))
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--print", action="store_true", dest="show")
    args = ap.parse_args(argv)

    cfg = yaml.safe_load(Path(args.config).read_text())
    plan, extra = allocate(cfg)
    values = to_values(plan, extra)

    Path(args.out).write_text(
        "# AUTO-GENERATED by scripts/allocate_resources.py — do not edit by hand.\n"
        + yaml.safe_dump(values, sort_keys=False))

    m = extra["meta"]
    print(f"Host: {m['host_memory']} RAM, {m['host_cpu']} CPU "
          f"→ allocatable {m['allocatable_memory']} / {m['allocatable_cpu']} CPU")
    for w in m["warnings"]:
        print(f"  ! {w}")
    if args.show:
        print(f"{'service':14} {'cpu req/lim':18} {'mem req/lim':22} storage")
        for svc in COMPUTE:
            r, l = plan[svc]["requests"], plan[svc]["limits"]
            st = extra["storage"].get(svc, "-")
            print(f"{svc:14} {r['cpu']+'/'+l['cpu']:18} {r['memory']+'/'+l['memory']:22} {st}")
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
