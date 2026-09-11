---
title: Denial of Service Vulnerability in libp2p-rendezvous
slug: 2026-09-libp2p-dos
description: A vulnerability in libp2p-rendezvous through version 0.17.1 allows malicious rendezvous servers to crash client nodes by providing an unbounded registration TTL value.
date: "2026-09-11T13:13:10Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:libp2p:libp2p-rendezvous:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - libp2p
vendors:
  - libp2p
products:
  - libp2p-rendezvous (<= 0.17.1)
cves:
  - id: CVE-2026-89146
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89146
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all applications currently using libp2p-rendezvous versions <= 0.17.1
      owner: Application Security
      due: 48h
      evidence: Source documentation identifies affected library versions.
  mitigation_plan:
    - priority: immediate
      action: Upgrade libp2p-rendezvous to the latest secure version once released
      owner: IT Operations
      addresses: CVE-2026-89146
      evidence: NVD vulnerability notice
  gaps:
    - Lack of vendor-provided patch version at time of report
---

The libp2p-rendezvous library, in versions up to and including 0.17.1, contains a vulnerability involving the improper validation of Time-to-Live (TTL) values received in discovery responses. An attacker operating a malicious rendezvous server can send a specially crafted discovery response containing an arbitrarily large or malformed TTL value. When the client node receives this response and attempts to perform arithmetic operations for its internal expiry timers, the input triggers an integer overflow. This overflow causes the application process to panic and results in an immediate crash. As a result, the vulnerability acts as a remote denial-of-service vector against any libp2p node relying on the affected rendezvous library for peer discovery. Defenders should identify services utilizing libp2p-rendezvous and update to the patched version once available.

## Impact

Successful exploitation results in the remote termination of the libp2p-rendezvous client process, leading to service disruption. This vulnerability impacts any system utilizing this library for P2P networking, potentially affecting decentralized applications, distributed data systems, or custom P2P-based network services.

## Recommendation

Prioritize patching of all systems utilizing libp2p-rendezvous to a version beyond 0.17.1 as soon as an update is released by the maintainers. Monitor system logs for frequent process crashes or unexpected panics in applications leveraging this specific library. Conduct an inventory check of software dependencies to identify the inclusion of libp2p-rendezvous versions 0.17.1 or lower.
