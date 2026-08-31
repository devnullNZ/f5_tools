#!/usr/bin/env python3
"""
f5_validate_migration.py — Compare a baseline (i5800) inventory snapshot
against a post-migration (r5800) snapshot produced by f5_inventory.py, and
optionally do a live SNAT traffic check against the new pair.

Modes
-----
diff   Structural comparison of the two JSON snapshots: missing/extra
       objects per partition, and field-level drift on matched objects.
       Includes a dedicated SNAT section (snatpools, snat-translations,
       and each virtual's sourceAddressTranslation binding).

live   Connects to the target (r5800) and pulls stats for every
       snat-translation and virtual server to confirm traffic is actually
       flowing through the new SNAT addresses post-cutover — a structural
       match doesn't prove traffic is using it.

Usage
-----
    python3 f5_validate_migration.py diff \
        --baseline dc1_i5800_baseline.json --target dc1_r5800_postmigration.json

    export F5_PASSWORD=xxxxx
    python3 f5_validate_migration.py live \
        --target dc1_r5800_postmigration.json --host bigip-dc1-a-new.example.com --user admin
"""

import argparse
import getpass
import json
import os
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------- diff mode ----------

def load(path):
    with open(path) as f:
        return json.load(f)


def index_by_name(items):
    return {i["name"]: i for i in items}


def diff_object_list(kind, baseline_items, target_items, key_fields=None):
    """Return (missing, extra, drifted) for a list of dict objects keyed by name."""
    b = index_by_name(baseline_items) if baseline_items and isinstance(baseline_items[0], dict) else None
    if b is None:
        # simple name lists (irule, cert)
        bset, tset = set(baseline_items), set(target_items)
        return sorted(bset - tset), sorted(tset - bset), []

    t = index_by_name(target_items)
    missing = sorted(set(b) - set(t))
    extra = sorted(set(t) - set(b))
    drifted = []
    for name in sorted(set(b) & set(t)):
        fields = key_fields or [k for k in b[name].keys() if k != "name"]
        diffs = {f: (b[name].get(f), t[name].get(f)) for f in fields if b[name].get(f) != t[name].get(f)}
        if diffs:
            drifted.append((name, diffs))
    return missing, extra, drifted


def run_diff(baseline_path, target_path):
    baseline = load(baseline_path)
    target = load(target_path)

    b_parts = baseline["partitions"]
    t_parts = target["partitions"]

    all_partitions = sorted(set(b_parts) | set(t_parts))
    part_missing = sorted(set(b_parts) - set(t_parts))
    part_extra = sorted(set(t_parts) - set(b_parts))

    print(f"=== Partition coverage ===")
    print(f"Baseline: {baseline['host']}  Target: {target['host']}")
    if part_missing:
        print(f"MISSING on target: {', '.join(part_missing)}")
    if part_extra:
        print(f"EXTRA on target (not in baseline): {', '.join(part_extra)}")
    if not part_missing and not part_extra:
        print("All partitions present on both sides.")

    object_types = [
        ("virtual", ["destination", "mask", "pool", "source", "sourceAddressTranslation", "vlans", "enabled"]),
        ("pool", ["loadBalancingMode", "monitor", "members"]),
        ("node", ["address", "state"]),
        ("snatpool", ["members"]),
        ("snat_translation", ["address", "enabled"]),
        ("self", ["address", "vlan", "trafficGroup"]),
        ("vlan", ["tag"]),
        ("route", ["network", "gw"]),
        ("route_domain", ["id", "vlans"]),
        ("irule", None),
        ("cert", None),
    ]

    overall_problems = 0

    for partition in [p for p in all_partitions if p in b_parts and p in t_parts]:
        b_data = b_parts[partition]
        t_data = t_parts[partition]
        partition_lines = []

        for kind, key_fields in object_types:
            missing, extra, drifted = diff_object_list(kind, b_data.get(kind, []), t_data.get(kind, []), key_fields)
            if missing:
                partition_lines.append(f"  [{kind}] MISSING on target: {', '.join(missing)}")
            if extra:
                partition_lines.append(f"  [{kind}] extra on target (not in baseline): {', '.join(extra)}")
            for name, diffs in drifted:
                diff_str = "; ".join(f"{f}: {bv!r} -> {tv!r}" for f, (bv, tv) in diffs.items())
                partition_lines.append(f"  [{kind}] DRIFT '{name}': {diff_str}")

        if partition_lines:
            overall_problems += len(partition_lines)
            print(f"\n=== Partition: {partition} ===")
            print("\n".join(partition_lines))

    print(f"\n=== SNAT-specific cross-check ===")
    snat_problems = 0
    for partition in [p for p in all_partitions if p in b_parts and p in t_parts]:
        b_vs = index_by_name(b_parts[partition].get("virtual", []))
        t_vs = index_by_name(t_parts[partition].get("virtual", []))
        for name in sorted(set(b_vs) & set(t_vs)):
            b_sat = b_vs[name].get("sourceAddressTranslation", {})
            t_sat = t_vs[name].get("sourceAddressTranslation", {})
            if b_sat.get("type") != t_sat.get("type") or b_sat.get("pool") != t_sat.get("pool"):
                snat_problems += 1
                print(
                    f"  [{partition}] virtual '{name}' SNAT binding changed: "
                    f"{b_sat} -> {t_sat}"
                )
    if snat_problems == 0:
        print("  All virtual server SNAT bindings (automap/snatpool/none) match baseline.")

    print(f"\n=== Summary ===")
    print(f"Structural issues: {overall_problems}")
    print(f"SNAT binding mismatches: {snat_problems}")
    if overall_problems == 0 and snat_problems == 0:
        print("Clean diff. Proceed to live traffic validation after cutover.")
        return 0
    return 1


# ---------- live mode ----------

def get_session(host, user, password, verify_tls):
    resp = requests.post(
        f"https://{host}/mgmt/shared/authn/login",
        json={"username": user, "password": password, "loginProviderName": "tmos"},
        verify=verify_tls,
        timeout=30,
    )
    resp.raise_for_status()
    token = resp.json()["token"]["token"]
    session = requests.Session()
    session.headers.update({"X-F5-Auth-Token": token})
    session.verify = verify_tls
    return session


def get_stats_value(session, host, path):
    resp = session.get(f"https://{host}{path}", timeout=30)
    resp.raise_for_status()
    data = resp.json()
    entries = data.get("entries", {})
    # iControl REST stats responses are keyed by a full URL; grab the first entry's nestedStats
    for _, v in entries.items():
        return v.get("nestedStats", {}).get("entries", {})
    return {}


def run_live(target_path, host, user, password, verify_tls):
    target = load(target_path)
    session = get_session(host, user, password, verify_tls)

    print(f"=== Live SNAT traffic check on {host} ===")
    zero_traffic = []

    for partition, data in target["partitions"].items():
        for st in data.get("snat_translation", []):
            name = st["name"]
            path = f"/mgmt/tm/ltm/snat-translation/~{partition}~{name}/stats"
            try:
                stats = get_stats_value(session, host, path)
                cur_conns = stats.get("clientside.curConns", {}).get("value", 0)
                tot_conns = stats.get("clientside.totConns", {}).get("value", 0)
                status = "OK" if tot_conns > 0 else "NO TRAFFIC YET"
                if tot_conns == 0:
                    zero_traffic.append(f"{partition}/{name}")
                print(f"  [{partition}] snat-translation '{name}': curConns={cur_conns} totConns={tot_conns} [{status}]")
            except requests.RequestException as e:
                print(f"  [{partition}] snat-translation '{name}': ERROR fetching stats: {e}")

        for vs in data.get("virtual", []):
            sat = vs.get("sourceAddressTranslation", {})
            if sat.get("type") == "snat" and sat.get("pool"):
                name = vs["name"]
                path = f"/mgmt/tm/ltm/virtual/~{partition}~{name}/stats"
                try:
                    stats = get_stats_value(session, host, path)
                    tot_conns = stats.get("clientside.totConns", {}).get("value", 0)
                    print(f"  [{partition}] virtual '{name}' (snatpool {sat['pool']}): totConns={tot_conns}")
                except requests.RequestException as e:
                    print(f"  [{partition}] virtual '{name}': ERROR fetching stats: {e}")

    if zero_traffic:
        print(f"\nNo traffic yet through: {', '.join(zero_traffic)}")
        print("Expected immediately after cutover — re-run once traffic has ramped.")
    else:
        print("\nAll SNAT translation addresses show traffic.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)

    d = sub.add_parser("diff")
    d.add_argument("--baseline", required=True)
    d.add_argument("--target", required=True)

    l = sub.add_parser("live")
    l.add_argument("--target", required=True, help="Post-migration snapshot JSON (defines what to check)")
    l.add_argument("--host", required=True, help="r5800 mgmt host to query live stats from")
    l.add_argument("--user", required=True)
    l.add_argument("--verify-tls", action="store_true")

    args = ap.parse_args()

    if args.mode == "diff":
        sys.exit(run_diff(args.baseline, args.target))
    else:
        password = os.environ.get("F5_PASSWORD") or getpass.getpass(f"Password for {args.user}@{args.host}: ")
        run_live(args.target, args.host, args.user, password, args.verify_tls)


if __name__ == "__main__":
    main()
