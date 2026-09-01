# ixx00 → rxx00 Migration Checklist (LTM-only, TMOS upgrade)

## 1. Pre-migration
- [ ] Confirm target TMOS version supports r5800 and is the version you're standardizing on.
- [ ] Confirm rxx00 base registration keys are on hand (per device) — licensing is separate from the UCS restore.
- [ ] Confirm interface/trunk mapping on rxx00 vs ixx00 (numbering can differ) and pre-stage cabling/LACP accordingly.
- [ ] Run `f5_inventory.py` against the **active** member of each ixx00 pair (one export per DC) → baseline JSON.
- [ ] Take a fresh UCS archive on the source pair being cut over (`tmsh save sys ucs /var/tmp/dcX-premigration.ucs`), pull it off-box.

## 2. Build the rxx00 pair
- [ ] Rack, cable, base-license the rxx00 pair (do this *before* restoring config — base registration key is tied to hardware, not portable from the old device).
- [ ] Install target TMOS version on both r5800 nodes.
- [ ] Restore the UCS onto **node 1 only** of the new pair.
- [ ] Re-check module provisioning (`tmsh list sys provision`) — confirm LTM only, matching source.
- [ ] Verify VLAN/interface bindings came across correctly given any interface renumbering.
- [ ] Bring node 2 up clean (no UCS restore on it) and establish the HA pair; let it pick up config via ConfigSync from node 1.
- [ ] Re-verify licensing/provisioning on node 2 after sync.

## 3. Post-restore validation (pre-cutover, no live traffic)
- [ ] Run `f5_inventory.py` against the new rxx00 pair → post-migration JSON.
- [ ] Run `f5_validate_migration.py diff --baseline <dc>_ixx00_baseline.json --target <dc>_rxx00_postmigration.json`
- [ ] Resolve every MISSING / DRIFT / SNAT binding mismatch before proceeding. Pay particular attention to:
  - snatpool membership (addresses must match exactly, not just count)
  - snat-translation addresses (these are routable addresses — confirm they're actually reachable on the new VLANs)
  - virtual server `sourceAddressTranslation` binding (automap vs explicit snatpool) — a UCS restore across platforms occasionally normalizes settings; don't assume they carried over silently.

## 4. Cutover
- [ ] Do one DC/pair at a time, not both simultaneously.
- [ ] Cut over floating self-IPs / route advertisement / upstream routing to point at the new pair.
- [ ] Confirm route domains (if in use per-partition) came across and are bound to the correct VLANs.

## 5. Post-cutover live validation
- [ ] Run `f5_validate_migration.py live --target <dc>_r5800_postmigration.json --host <new-pair-mgmt-ip> --user <user>`
- [ ] Confirm every snat-translation shows non-zero `totConns` once real traffic ramps — a structural match doesn't prove SNAT is actually being used; this is the check that does.
- [ ] Spot-check pool member health per partition (`tmsh show ltm pool members` or via REST `/mgmt/tm/ltm/pool/~part~name/members/stats`) to confirm monitors are passing from the new hardware's egress paths (SNAT address changes can affect monitor source IP visibility if ACLs upstream are IP-specific).
- [ ] Decommission old ixx00 pair only after a full traffic-cycle (peak + off-peak) has been validated clean.

## 6. Repeat for second DC
- [ ] Same sequence, independent pair — don't run both DCs' cutovers in parallel the first time through, so you can adjust the process based on DC1 lessons.
