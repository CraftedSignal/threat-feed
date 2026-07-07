---
title: Zebra Node Denial-of-Service via IPv4-Mapped Mempool Misbehavior Panic (CVE-2026-52829)
slug: 2026-07-zebra-mempool-panic
description: A remote unauthenticated peer can exploit an address normalization mismatch in Zebra's address book when connecting via IPv4 to a dual-stack IPv6 listener on a Linux host, by then advertising an invalid mempool transaction, which triggers a deterministic assertion panic after a 30-second delay, causing the `zebrad` process to terminate, leading to persistent denial of service.
date: "2026-07-03T11:25:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - linux
  - rust
vendors:
  - Zebra
products:
  - zebrad <= 4.4.1
  - zebra-network <= 6.0.0
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: The assertion fails... `panic = "abort"` terminates the process.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-63wg-wjjj-7cp8
---

A high-severity vulnerability, CVE-2026-52829, affects Zebra `zebrad` nodes up to version `4.4.1` and `zebra-network` up to `6.0.0`, potentially allowing a remote denial-of-service. An address normalization mismatch occurs when a peer connects via IPv4 to a dual-stack IPv6 listener (the default `[::]` address on Linux with `net.ipv6.bindv6only=0`), and subsequently triggers a mempool misbehavior penalty by advertising an invalid transaction. The `zebrad` software stores the peer's address in a canonical IPv4 form during the initial handshake, but later attempts to update its misbehavior status using the raw IPv4-mapped IPv6 address from the transient socket. This inconsistency leads to a deterministic assertion panic after a 30-second delay, terminating the `zebrad` process. This issue is critical for any `zebrad` node synchronized near the chain tip in a production environment as it enables persistent downtime.

## Attack Chain

1.  An unauthenticated attacker initiates an IPv4 connection to a vulnerable `zebrad` node listening on a dual-stack IPv6 address (e.g., `[::]` on Linux with `net.ipv6.bindv6only=0`).
2.  During the P2P handshake, the `zebrad` node's address book canonicalizes the IPv4-mapped IPv6 address (e.g., `::ffff:127.0.0.1`) to a plain IPv4 address (e.g., `127.0.0.1`) and stores it.
3.  The attacker advertises an invalid mempool transaction, such as a coinbase transaction, which the `zebrad` node attempts to download.
4.  The `zebrad` node identifies the transaction as invalid and queues a misbehavior penalty for the peer, forwarding the raw IPv4-mapped IPv6 transient socket address.
5.  After a 30-second batch flush, the address book attempts to apply the misbehavior update to the stored peer entry.
6.  An internal assertion (`previous.addr == self.addr()`) fails because the canonical IPv4 address originally stored does not match the raw IPv4-mapped IPv6 address received for the misbehavior update.
7.  This mismatch triggers a `panic = "abort"`, causing the `zebrad` process to terminate, resulting in a denial-of-service.
8.  The attacker can repeat this sequence after each node restart, leading to persistent downtime.

## Impact

This vulnerability allows any remote, unauthenticated peer to deterministically crash a synced Zebra node running in its default Linux dual-stack configuration. The attack requires no mining capability, RPC access, funds, or special privileges, making it highly accessible to adversaries. The `zebrad` process terminates abruptly, leading to service disruption. Since the attack can be repeated reliably after each restart, it poses a significant threat of persistent denial of service, impacting the availability and stability of the Zebra network. Nodes operating as part of critical infrastructure, such as those maintaining blockchain consensus, would face severe operational issues.

## Recommendation

*   Patch CVE-2026-52829 by upgrading `zebrad` to version `4.5.0` or higher immediately.
*   As a temporary workaround, configure `zebrad`'s `listen_addr` to bind only to an IPv4-only address (e.g., `0.0.0.0:8233`) to prevent the use of IPv4-mapped IPv6 representations.
*   Alternatively, on Linux hosts, set the kernel parameter `net.ipv6.bindv6only=1` to disable dual-stack acceptance on IPv6 listeners, thus preventing the vulnerable condition described in CVE-2026-52829.
