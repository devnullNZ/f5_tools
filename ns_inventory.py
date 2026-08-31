#!/usr/bin/env python3
"""
ns_inventory.py — NetScaler ns.conf discovery/inventory tool

Purpose:
    Scope an LTM-only NetScaler -> F5 BIG-IP migration by parsing an ns.conf
    file and reporting on the distinct object types, LB methods, monitor
    types, persistence types, SSL usage, and SNIP usage in play. This is a
    read-only reconnaissance tool — it does NOT translate config, it tells
    you how big/varied the translation effort actually is before you build
    the mapping tables.

Usage:
    python3 ns_inventory.py /path/to/ns.conf
    python3 ns_inventory.py /path/to/ns.conf --json report.json
    python3 ns_inventory.py /path/to/ns.conf --csv-dir ./inventory_csv/

Notes:
    - ns.conf lines are shell-style tokenized: `add lb vserver "my vserver" ...`
      Quoted names with spaces are supported.
    - Flags (`-lbMethod ROUNDROBIN`) are parsed generically into a dict per
      object so this survives NetScaler version differences reasonably well.
    - This targets the common LTM-relevant command set. GSLB, AppFlow,
      Citrix Gateway/VPN, and AppFirewall lines are intentionally ignored
      (out of scope per stated LTM-only migration) but are counted so you
      can confirm nothing unexpected is present.
"""

import argparse
import csv
import json
import re
import shlex
import sys
from collections import Counter, defaultdict
from pathlib import Path


# Command prefixes we actively parse into structured objects.
LTM_RELEVANT_PREFIXES = {
    "add server",
    "add serviceGroup",
    "add service",
    "add lb vserver",
    "add lb monitor",
    "add ssl certKey",
    "add ns ip",
    "bind lb vserver",
    "bind serviceGroup",
    "bind ssl vserver",
    "set ssl vserver",
    "set lb vserver",
}

# Prefixes that indicate out-of-scope (non-LTM) features, counted but not parsed.
OUT_OF_SCOPE_PREFIXES = {
    "add gslb": "GSLB",
    "add appfw": "AppFirewall (WAF)",
    "add vpn": "Citrix Gateway/VPN",
    "add ns acl": "Network ACL",
    "add authentication": "AAA/Authentication",
    "add cache": "Integrated Caching",
    "add rewrite": "Rewrite policy",
    "add responder": "Responder policy",
    "add appflow": "AppFlow",
    "add ns rpcNode": "RPC Node (HA-related, not migrated)",
}


def tokenize(line: str):
    """Shell-style tokenize an ns.conf line, tolerating its quoting style."""
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        # Unbalanced quotes -- fall back to naive split rather than crashing
        # on one malformed line in a 400-vserver config.
        return line.split()


def parse_flags(tokens, start_idx):
    """
    Parse trailing `-flagName value [value2 ...]` pairs into a dict.
    NetScaler flags are single-valued in the vast majority of cases; a
    following token that itself starts with '-' ends the previous flag's
    value list.
    """
    flags = {}
    i = start_idx
    current_flag = None
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("-") and not _looks_like_negative_number(tok):
            current_flag = tok[1:]
            flags[current_flag] = []
        elif current_flag is not None:
            flags[current_flag].append(tok)
        i += 1
    # Collapse single-value flag lists to a scalar for convenience.
    return {k: (v[0] if len(v) == 1 else " ".join(v)) for k, v in flags.items()}


def _looks_like_negative_number(tok: str) -> bool:
    return bool(re.match(r"^-\d+(\.\d+)?$", tok))


class Inventory:
    def __init__(self):
        self.servers = {}          # name -> {ip}
        self.service_groups = {}   # name -> {serviceType, flags, members: []}
        self.services = {}         # name -> {server, serviceType, port, flags}
        self.monitors = {}         # name -> {type, flags}
        self.vservers = {}         # name -> {serviceType, ip, port, flags, bound_services: []}
        self.certkeys = {}         # name -> {flags}
        self.snips = []            # list of {ip, mask, flags}
        self.ssl_vserver_binds = defaultdict(list)  # vserver -> [certkey names]
        self.out_of_scope_counts = Counter()
        self.unparsed_ltm_lines = []
        self.total_lines = 0
        self.parse_errors = []

    # -- individual line handlers -----------------------------------------

    def handle_add_server(self, tokens):
        # add server <name> <ip> [flags]
        if len(tokens) < 4:
            self.unparsed_ltm_lines.append(" ".join(tokens))
            return
        name, ip = tokens[2], tokens[3]
        self.servers[name] = {"ip": ip}

    def handle_add_servicegroup(self, tokens):
        # add serviceGroup <name> <serviceType> [flags]
        if len(tokens) < 4:
            self.unparsed_ltm_lines.append(" ".join(tokens))
            return
        name, svc_type = tokens[2], tokens[3]
        flags = parse_flags(tokens, 4)
        self.service_groups[name] = {"serviceType": svc_type, "flags": flags, "members": []}

    def handle_add_service(self, tokens):
        # add service <name> <server> <serviceType> <port> [flags]
        if len(tokens) < 6:
            self.unparsed_ltm_lines.append(" ".join(tokens))
            return
        name, server, svc_type, port = tokens[2], tokens[3], tokens[4], tokens[5]
        flags = parse_flags(tokens, 6)
        self.services[name] = {
            "server": server, "serviceType": svc_type, "port": port, "flags": flags
        }

    def handle_add_lb_monitor(self, tokens):
        # add lb monitor <name> <type> [flags]
        if len(tokens) < 5:
            self.unparsed_ltm_lines.append(" ".join(tokens))
            return
        name, mon_type = tokens[3], tokens[4]
        flags = parse_flags(tokens, 5)
        self.monitors[name] = {"type": mon_type, "flags": flags}

    def handle_add_lb_vserver(self, tokens):
        # add lb vserver <name> <serviceType> [<ip> <port>] [flags]
        if len(tokens) < 5:
            self.unparsed_ltm_lines.append(" ".join(tokens))
            return
        name, svc_type = tokens[3], tokens[4]
        ip, port, flag_start = None, None, 5
        if len(tokens) >= 7 and not tokens[5].startswith("-"):
            ip, port, flag_start = tokens[5], tokens[6], 7
        flags = parse_flags(tokens, flag_start)
        self.vservers[name] = {
            "serviceType": svc_type, "ip": ip, "port": port,
            "flags": flags, "bound_services": []
        }

    def handle_add_ssl_certkey(self, tokens):
        # add ssl certKey <name> [flags]
        if len(tokens) < 4:
            self.unparsed_ltm_lines.append(" ".join(tokens))
            return
        name = tokens[3]
        flags = parse_flags(tokens, 4)
        self.certkeys[name] = {"flags": flags}

    def handle_add_ns_ip(self, tokens):
        # add ns ip <ip> <mask> [-type SNIP|...]
        if len(tokens) < 5:
            self.unparsed_ltm_lines.append(" ".join(tokens))
            return
        ip, mask = tokens[3], tokens[4]
        flags = parse_flags(tokens, 5)
        if flags.get("type", "").upper() == "SNIP":
            self.snips.append({"ip": ip, "mask": mask, "flags": flags})

    def handle_bind_lb_vserver(self, tokens):
        # bind lb vserver <vserver> <service_or_servicegroup>
        if len(tokens) < 4:
            self.unparsed_ltm_lines.append(" ".join(tokens))
            return
        vserver, target = tokens[3], tokens[4] if len(tokens) > 4 else None
        if target and vserver in self.vservers:
            self.vservers[vserver]["bound_services"].append(target)

    def handle_bind_servicegroup(self, tokens):
        # bind serviceGroup <name> <server> <port> [flags]
        if len(tokens) < 5:
            self.unparsed_ltm_lines.append(" ".join(tokens))
            return
        name, server, port = tokens[2], tokens[3], tokens[4]
        if name in self.service_groups:
            self.service_groups[name]["members"].append({"server": server, "port": port})

    def handle_bind_ssl_vserver(self, tokens):
        # bind ssl vserver <name> -certkeyName <certkey>
        if len(tokens) < 4:
            self.unparsed_ltm_lines.append(" ".join(tokens))
            return
        name = tokens[3]
        flags = parse_flags(tokens, 4)
        ck = flags.get("certkeyName")
        if ck:
            self.ssl_vserver_binds[name].append(ck)


HANDLERS = {
    "add server": Inventory.handle_add_server,
    "add serviceGroup": Inventory.handle_add_servicegroup,
    "add service": Inventory.handle_add_service,
    "add lb monitor": Inventory.handle_add_lb_monitor,
    "add lb vserver": Inventory.handle_add_lb_vserver,
    "add ssl certKey": Inventory.handle_add_ssl_certkey,
    "add ns ip": Inventory.handle_add_ns_ip,
    "bind lb vserver": Inventory.handle_bind_lb_vserver,
    "bind serviceGroup": Inventory.handle_bind_servicegroup,
    "bind ssl vserver": Inventory.handle_bind_ssl_vserver,
}


def match_prefix(line: str, prefixes):
    for p in prefixes:
        if line.startswith(p + " ") or line == p:
            return p
    return None


def parse_ns_conf(path: Path) -> Inventory:
    inv = Inventory()
    with path.open("r", errors="replace") as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            inv.total_lines += 1
            if not line or line.startswith("#"):
                continue

            oos_prefix = match_prefix(line, OUT_OF_SCOPE_PREFIXES.keys())
            if oos_prefix:
                inv.out_of_scope_counts[OUT_OF_SCOPE_PREFIXES[oos_prefix]] += 1
                continue

            ltm_prefix = match_prefix(line, LTM_RELEVANT_PREFIXES)
            if not ltm_prefix:
                continue  # not an object type we track (e.g. HA config, NTP, SNMP)

            try:
                tokens = tokenize(line)
                handler = HANDLERS.get(ltm_prefix)
                if handler:
                    handler(inv, tokens)
                else:
                    inv.unparsed_ltm_lines.append(line)
            except Exception as e:  # noqa: BLE001 - keep scanning on bad lines
                inv.parse_errors.append(f"line {lineno}: {e}: {line[:120]}")
    return inv


def build_report(inv: Inventory) -> dict:
    lb_methods = Counter()
    persistence_types = Counter()
    vserver_service_types = Counter()
    ssl_vserver_count = 0

    for name, v in inv.vservers.items():
        flags = v["flags"]
        method = flags.get("lbMethod", "ROUNDROBIN (default)")
        lb_methods[method] += 1
        if "persistenceType" in flags:
            persistence_types[flags["persistenceType"]] += 1
        else:
            persistence_types["NONE"] += 1
        vserver_service_types[v["serviceType"]] += 1
        if v["serviceType"] in ("SSL", "SSL_TCP", "SSL_BRIDGE") or name in inv.ssl_vserver_binds:
            ssl_vserver_count += 1

    monitor_types = Counter(m["type"] for m in inv.monitors.values())

    # Monitors actually referenced by a service/servicegroup (vs defined-but-unused)
    referenced_monitors = Counter()
    for svc in inv.services.values():
        mon = svc["flags"].get("monitorName")
        if mon:
            referenced_monitors[mon] += 1

    report = {
        "summary": {
            "total_lines_scanned": inv.total_lines,
            "vservers": len(inv.vservers),
            "servers": len(inv.servers),
            "service_groups": len(inv.service_groups),
            "services": len(inv.services),
            "monitors_defined": len(inv.monitors),
            "certkeys": len(inv.certkeys),
            "snips": len(inv.snips),
            "unparsed_ltm_line_count": len(inv.unparsed_ltm_lines),
            "parse_error_count": len(inv.parse_errors),
        },
        "vserver_service_types": dict(vserver_service_types),
        "lb_methods_in_use": dict(lb_methods.most_common()),
        "persistence_types_in_use": dict(persistence_types.most_common()),
        "monitor_types_defined": dict(monitor_types.most_common()),
        "ssl_vserver_count": ssl_vserver_count,
        "certkey_count": len(inv.certkeys),
        "snip_count": len(inv.snips),
        "out_of_scope_features_present": dict(inv.out_of_scope_counts),
        "unparsed_ltm_lines_sample": inv.unparsed_ltm_lines[:25],
        "parse_errors_sample": inv.parse_errors[:25],
    }
    return report


def print_human_report(report: dict):
    s = report["summary"]
    print("=" * 70)
    print("NetScaler ns.conf Inventory Report (LTM-only migration scoping)")
    print("=" * 70)
    print(f"Lines scanned:          {s['total_lines_scanned']}")
    print(f"LB vservers:            {s['vservers']}")
    print(f"Servers (backend IPs):  {s['servers']}")
    print(f"Service groups:        {s['service_groups']}")
    print(f"Services (individual):  {s['services']}")
    print(f"Monitors defined:       {s['monitors_defined']}")
    print(f"SSL certKeys:           {s['certkeys']}")
    print(f"SNIPs:                  {s['snips']}")
    if s["unparsed_ltm_line_count"] or s["parse_error_count"]:
        print(f"⚠ Unparsed LTM lines:   {s['unparsed_ltm_line_count']}  "
              f"(sample below — check these manually)")
        print(f"⚠ Parse errors:         {s['parse_error_count']}")

    print("\n--- Vserver service types ---")
    for k, v in report["vserver_service_types"].items():
        print(f"  {k:<15} {v}")

    print("\n--- LB methods in use (this is your mapping-table scope) ---")
    for k, v in report["lb_methods_in_use"].items():
        print(f"  {k:<25} {v} vserver(s)")

    print("\n--- Persistence types in use ---")
    for k, v in report["persistence_types_in_use"].items():
        print(f"  {k:<25} {v} vserver(s)")

    print("\n--- Monitor types defined (map each of these to an F5 monitor type) ---")
    for k, v in report["monitor_types_defined"].items():
        print(f"  {k:<25} {v} monitor(s)")

    print(f"\nSSL-terminating vservers: {report['ssl_vserver_count']}")
    print(f"SNIPs found:              {report['snip_count']}  "
          f"(review each for SNIP-vs-SNAT-pool intent on F5 side)")

    if report["out_of_scope_features_present"]:
        print("\n--- Out-of-scope features detected (confirm these are truly unused) ---")
        for k, v in report["out_of_scope_features_present"].items():
            print(f"  ⚠ {k:<30} {v} line(s)")
    else:
        print("\nNo out-of-scope (GSLB/AppFw/VPN/etc.) config detected — LTM-only confirmed.")

    if report["unparsed_ltm_lines_sample"]:
        print("\n--- Sample of unparsed LTM-relevant lines (check manually) ---")
        for line in report["unparsed_ltm_lines_sample"]:
            print(f"  {line}")

    if report["parse_errors_sample"]:
        print("\n--- Sample parse errors ---")
        for err in report["parse_errors_sample"]:
            print(f"  {err}")

    print("\n" + "=" * 70)
    print("Next step: use the LB methods / monitor types / persistence types")
    print("lists above to build the NetScaler->F5 mapping table before writing")
    print("the translation script's emit pass.")
    print("=" * 70)


def write_csvs(report: dict, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    tables = {
        "lb_methods.csv": report["lb_methods_in_use"],
        "persistence_types.csv": report["persistence_types_in_use"],
        "monitor_types.csv": report["monitor_types_defined"],
        "vserver_service_types.csv": report["vserver_service_types"],
        "out_of_scope_features.csv": report["out_of_scope_features_present"],
    }
    for filename, data in tables.items():
        path = out_dir / filename
        with path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["value", "count"])
            for k, v in data.items():
                writer.writerow([k, v])
    print(f"CSV tables written to {out_dir}/")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ns_conf", type=Path, help="Path to ns.conf")
    ap.add_argument("--json", type=Path, help="Also write the full report as JSON to this path")
    ap.add_argument("--csv-dir", type=Path, help="Also write per-category CSV tables to this directory")
    args = ap.parse_args()

    if not args.ns_conf.exists():
        print(f"Error: {args.ns_conf} not found", file=sys.stderr)
        sys.exit(1)

    inv = parse_ns_conf(args.ns_conf)
    report = build_report(inv)
    print_human_report(report)

    if args.json:
        args.json.write_text(json.dumps(report, indent=2))
        print(f"\nJSON report written to {args.json}")

    if args.csv_dir:
        write_csvs(report, args.csv_dir)


if __name__ == "__main__":
    main()
