---
brief_id: brief-2026-11-05-gdb-buffer-overflow
event_id: brief-2026-11-05-gdb-buffer-overflow
revision: 2
activity_at: "2026-11-21T10:51:53Z"
revision_history:
  - revision: 2
    at: "2026-11-21T10:51:53Z"
    checksum: sha256:b0fbb27562763b006820454aaa8062425261e3e5b8365cd0b7d5e082e771ac6e
    summary: added coverage for Red Hat Enterprise Linux 6 (gdb) +4 products
    changed_fields:
      - action_plan
      - affected_os
      - affected_products
      - affected_vendors
      - content
      - cpes
      - has_poc
      - lastmod
      - poc_references
      - priority_signals
      - qa_status
      - references
      - summary
      - tags
      - title
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=13F7A1F4-F689-563A-87AC-3D713618C4DD&utm_source=rss&utm_medium=rss
title: 'GDB: Remote Code Execution via Malicious Debug Target (CVE-2026-121994)'
slug: 2026-11-gdb-buffer-overflow
description: A stack buffer overflow vulnerability in the GDB remote protocol handler allows an attacker-controlled debug target to execute arbitrary code on a connecting GDB client (CVE-2026-121994).
date: "2026-11-05T18:23:18Z"
lastmod: "2026-11-21T10:51:39Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: All information grounded in Red Hat primary source and Sploitus advisory.
cpes:
  - cpe:2.3:o:redhat:enterprise_linux:6:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:7:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:9:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=13F7A1F4-F689-563A-87AC-3D713618C4DD&utm_source=rss&utm_medium=rss
tags:
  - cve
  - remote-code-execution
  - gdb
  - linux
vendors:
  - Red Hat
products:
  - Red Hat Enterprise Linux 6 (gdb)
  - Red Hat Enterprise Linux 7 (gdb)
  - Red Hat Enterprise Linux 8 (gdb, gcc-toolset-14-gdb, gcc-toolset-15-gdb)
  - Red Hat Enterprise Linux 9 (gdb)
  - Red Hat Hardened Images (gdb)
affected_os:
  - Red Hat Enterprise Linux 6
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A stack buffer overflow in the GDB client's remote protocol handler allows an attacker-controlled debug target to execute arbitrary code in the GDB process.
    confidence_band: high
cves:
  - id: CVE-2026-121994
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121994
  - https://cveawg.mitre.org/api/cve/CVE-2026-121994
  - https://bugzilla.redhat.com/show_bug.cgi?id=2565676
  - https://sploitus.com/exploit?id=13F7A1F4-F689-563A-87AC-3D713618C4DD
  - https://sploitus.com/exploit?id=13F7A1F4-F689-563A-87AC-3D713618C4DD&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all Linux systems running GDB to determine exposure to affected packages.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-121994 vulnerability in GDB.
  hunt_leads:
    - lead: Monitor GDB network connections to external or non-whitelisted remote debug endpoints.
      technique_id: T1071
      data_needed:
        - Network connection logs including GDB process image and destination IP
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: GDB client connects to remote RSP debug targets.
  mitigation_plan:
    - priority: immediate
      action: Apply official Red Hat package updates once available; enforce SELinux in enforcing mode.
      owner: IT Operations
      addresses: CVE-2026-121994
      evidence: Red Hat CME mitigation guidance.
updates:
  - at: "2026-11-21T10:51:39Z"
    level: L2
    summary: added coverage for Red Hat Enterprise Linux 6 (gdb) +4 products
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=13F7A1F4-F689-563A-87AC-3D713618C4DD&utm_source=rss&utm_medium=rss
---

## Overview
CVE-2026-121994 is a stack buffer overflow vulnerability in the GDB remote protocol handler, specifically within the `fetch_register_using_p` function. An attacker can supply a specially crafted register reply via the remote serial protocol (RSP) that exceeds the size of the allocated buffer, leading to arbitrary code execution or stack disclosure. This vulnerability affects various Red Hat Enterprise Linux (RHEL) versions that bundle affected GDB packages. A proof-of-concept (PoC) exploit is publicly available, which uses a malicious Python-based debug stub to target GDB clients.

## Impact
Successful exploitation allows an attacker to gain control over the GDB process with the privileges of the user running the tool. This could result in unauthorized code execution or the disclosure of sensitive stack information, potentially compromising development or production environments where remote debugging is performed.

## Recommendation
- Upgrade GDB to the patched versions provided by Red Hat to enforce bounds checking on RSP register replies.
- Until a patch is applied, strictly avoid connecting GDB to unverified or untrusted remote RSP stubs.
- Enforce SELinux in enforcing mode to limit the GDB process capabilities.
- Monitor GDB process activity for abnormal child process creation (e.g., shells) or unexpected network connections to untrusted debug targets.
