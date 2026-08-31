#!/usr/bin/env python3
"""
f5_inventory.py — Snapshot LTM configuration from a BIG-IP device, across all
(or selected) partitions, via iControl REST.

Purpose
-------
Run this against each i5800 (or the active member of each HA pair) BEFORE
the migration to capture a baseline. Run it again against each r5800 pair
AFTER the UCS restore + re-provisioning + relicensing to capture the
post-migration state. Feed both JSON files into f5_validate_migration.py.

Object types captured (LTM-only estate):
    virtual, pool (+members), node, snatpool, snat-translation,
    self-ip, vlan, route, route-domain, irule (names only), ssl-cert (names only)

Usage
-----
    export F5_PASSWORD=xxxxx
    python3 f5_inventory.py --host bigip-dc1-a.example.com --user admin \
        --partitions all -o dc1_i5800_baseline.json

    python3 f5_inventory.py --host bigip-dc1-a.example.com --user admin \
        --partitions PartitionA,PartitionB -o partial.json

Notes
-----
- Uses token-based auth (POST /mgmt/shared/authn/login), standard on 17.x.
- TLS verification is disabled by default (mgmt interfaces usually run a
  self-signed cert) — pass --verify-tls if yours has a real cert.
- $filter=partition eq 'X' is used to scope collection queries to a single
  partition. This is standard iControl REST OData-style filtering on 17.x;
  if your build behaves differently, drop --partitions down to a single
  known-good partition first and confirm output before running the full set.
"""

import argparse
import getpass
import json
import os
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

    # Extend token idle timeout — 11 partitions x several object types can
    # take a few minutes; default token timeout is 1200s (20 min).
    token_self_url = f"https://{host}/mgmt/shared/authz/tokens/{token}"
    try:
        session.patch(token_self_url, json={"timeout": 36000}, timeout=15)
    except requests.RequestException:
        pass  # non-fatal, just means the default timeout applies

    return session


def get_json(session, host, path, params=None):
    url = f"https://{host}{path}"
    resp = session.get(url, params=params, timeout=60)
    resp.raise_for_status()
    return resp.json()


def list_partitions(session, host):
    data = get_json(session, host, "/mgmt/tm/sys/partition")
    return [item["name"] for item in data.get("items", [])]


def collect_for_partition(session, host, partition):
    pfilter = {"$filter": f"partition eq '{partition}'"}
    result = {}

    # Virtual servers
    vs = get_json(session, host, "/mgmt/tm/ltm/virtual", pfilter)
    result["virtual"] = [
        {
            "name": v.get("name"),
            "destination": v.get("destination"),
            "mask": v.get("mask"),
            "pool": v.get("pool"),
            "source": v.get("source"),
            "sourceAddressTranslation": v.get("sourceAddressTranslation", {}),
            "vlansEnabled": v.get("vlansEnabled"),
            "vlans": v.get("vlans", []),
            "rules": v.get("rules", []),
            "enabled": v.get("enabled", True),
        }
        for v in vs.get("items", [])
    ]

    # Pools + members in one call
    pools = get_json(
        session, host, "/mgmt/tm/ltm/pool",
        {**pfilter, "expandSubcollections": "true"},
    )
    result["pool"] = [
        {
            "name": p.get("name"),
            "loadBalancingMode": p.get("loadBalancingMode"),
            "monitor": p.get("monitor"),
            "members": sorted(
                m.get("name") for m in p.get("membersReference", {}).get("items", [])
            ),
        }
        for p in pools.get("items", [])
    ]

    # Nodes
    nodes = get_json(session, host, "/mgmt/tm/ltm/node", pfilter)
    result["node"] = [
        {"name": n.get("name"), "address": n.get("address"), "state": n.get("state")}
        for n in nodes.get("items", [])
    ]

    # SNAT pools
    snatpools = get_json(session, host, "/mgmt/tm/ltm/snatpool", pfilter)
    result["snatpool"] = [
        {"name": sp.get("name"), "members": sorted(sp.get("members", []))}
        for sp in snatpools.get("items", [])
    ]

    # SNAT translations (static NAT-like translation addresses)
    snattrans = get_json(session, host, "/mgmt/tm/ltm/snat-translation", pfilter)
    result["snat_translation"] = [
        {
            "name": st.get("name"),
            "address": st.get("address"),
            "enabled": st.get("enabled", True),
        }
        for st in snattrans.get("items", [])
    ]

    # Self IPs
    selfips = get_json(session, host, "/mgmt/tm/net/self", pfilter)
    result["self"] = [
        {
            "name": s.get("name"),
            "address": s.get("address"),
            "vlan": s.get("vlan"),
            "trafficGroup": s.get("trafficGroup"),
            "allowService": s.get("allowService"),
        }
        for s in selfips.get("items", [])
    ]

    # VLANs
    vlans = get_json(session, host, "/mgmt/tm/net/vlan", pfilter)
    result["vlan"] = [
        {"name": v.get("name"), "tag": v.get("tag")} for v in vlans.get("items", [])
    ]

    # Routes
    routes = get_json(session, host, "/mgmt/tm/net/route", pfilter)
    result["route"] = [
        {"name": r.get("name"), "network": r.get("network"), "gw": r.get("gw")}
        for r in routes.get("items", [])
    ]

    # Route domains (relevant with per-partition tenancy)
    rds = get_json(session, host, "/mgmt/tm/net/route-domain", pfilter)
    result["route_domain"] = [
        {"name": rd.get("name"), "id": rd.get("id"), "vlans": rd.get("vlans", [])}
        for rd in rds.get("items", [])
    ]

    # iRules — names only, content diff isn't the point of a hardware move
    irules = get_json(session, host, "/mgmt/tm/ltm/rule", pfilter)
    result["irule"] = sorted(r.get("name") for r in irules.get("items", []))

    # SSL certs — names only, existence check
    certs = get_json(session, host, "/mgmt/tm/sys/file/ssl-cert", pfilter)
    result["cert"] = sorted(c.get("name") for c in certs.get("items", []))

    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="Management IP/hostname of the BIG-IP")
    ap.add_argument("--user", required=True)
    ap.add_argument("--partitions", default="all", help="'all' or comma-separated list")
    ap.add_argument("-o", "--output", required=True, help="Output JSON path")
    ap.add_argument("--verify-tls", action="store_true", help="Verify TLS cert on mgmt interface")
    args = ap.parse_args()

    password = os.environ.get("F5_PASSWORD") or getpass.getpass(f"Password for {args.user}@{args.host}: ")

    session = get_session(args.host, args.user, password, args.verify_tls)

    if args.partitions == "all":
        partitions = list_partitions(session, args.host)
    else:
        partitions = [p.strip() for p in args.partitions.split(",")]

    print(f"[{args.host}] Collecting {len(partitions)} partition(s): {', '.join(partitions)}", file=sys.stderr)

    snapshot = {"host": args.host, "partitions": {}}
    for p in partitions:
        print(f"[{args.host}]   -> {p}", file=sys.stderr)
        snapshot["partitions"][p] = collect_for_partition(session, args.host, p)

    with open(args.output, "w") as f:
        json.dump(snapshot, f, indent=2, sort_keys=True)

    print(f"[{args.host}] Wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
