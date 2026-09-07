---
title: Heap Buffer Overflow in 389 Directory Server SASL I/O Layer
slug: 2026-09-389-ds-heap-overflow
description: A heap buffer overflow vulnerability in the SASL I/O layer of 389-ds-base allows a remote authenticated attacker to trigger an unsigned subtraction underflow and cause memory corruption.
date: "2026-09-07T15:33:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:389_directory_server_project:389-ds-base:*:*:*:*:*:*:*:*
vendors:
  - 389 Directory Server
products:
  - 389-ds-base
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: After a successful SASL bind with integrity protection (SSF > 0), a remote authenticated attacker can cause a denial of service or potentially achieve remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-11774
    cvss: 7.6
    epss: 0.00796
  - id: CVE-2026-18355
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18355
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade 389-ds-base to the patched version once released by the vendor.
      owner: IT Operations
      due: 48h
      evidence: Source indicates a vulnerability requiring patching
  mitigation_plan:
    - priority: immediate
      action: Identify servers running 389-ds-base and schedule maintenance windows for patching.
      owner: IT Operations
      addresses: CVE-2026-18355
---

A heap buffer overflow vulnerability exists in the SASL I/O layer of 389 Directory Server (389-ds-base), specifically within the sasl_io_read_packet() function. The flaw occurs because the wrapped-record length read from the wire is insufficiently validated. When an attacker provides a small wire length (0, 1, or 2) during a SASL bind with integrity protection (SSF > 0), the application performs an unsigned subtraction underflow when calculating the buffer count. This logic error instructs the system to read approximately 4 GiB of data into a 1024-byte heap-allocated buffer. 

This vulnerability allows a remote authenticated attacker to trigger memory corruption, leading to a denial of service (DoS) or potentially remote code execution (RCE). This issue is distinct from the previously reported CVE-2026-11774, as the earlier mitigation only addressed upper-bound overflows and failed to account for these specific underflow scenarios.

## Impact

Successful exploitation of this flaw can result in a crash of the 389 Directory Server process, causing service disruption. Furthermore, the ability to trigger a heap overflow with attacker-controlled content provides a pathway for remote code execution, which could lead to full system compromise of servers running 389-ds-base.

## Recommendation

1. Review security patches provided by the 389 Directory Server project and apply updates to 389-ds-base immediately to address CVE-2026-18355.
2. Monitor service logs for unexpected 389 Directory Server process crashes or restarts, which may indicate attempted exploitation.
3. Restrict access to Directory Server management interfaces to trusted administrative segments to reduce the risk of exploitation by unauthorized or partially authenticated entities.
