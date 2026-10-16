---
title: Heap-Based Buffer Overflow in spice-server GLZ Encoder
slug: 2026-10-spice-server-heap-overflow
description: An authenticated attacker can trigger a heap-based buffer overflow in spice-server during VM live migration by exploiting an integer truncation vulnerability in the GLZ encoder dictionary restore path.
date: "2026-10-16T12:26:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:spice_project:spice-server:*:*:*:*:*:*:*:*
vendors:
  - Spice Project
products:
  - spice-server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated attacker can exploit this during VM live migration by sending a crafted max_encoders value.
    confidence_band: high
cves:
  - id: CVE-2026-105959
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105959
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade spice-server to the patched version provided by your distribution vendor.
      owner: IT Operations
      addresses: CVE-2026-105959
      evidence: NVD vulnerability disclosure
---

A critical integer truncation vulnerability (CVE-2026-105959) exists in the spice-server, specifically within the GLZ encoder dictionary restore path. The flaw occurs when a size_t allocation size is incorrectly truncated to an int when calling the memory allocation callback. An authenticated attacker acting as a SPICE client can leverage this vulnerability during the live migration of a virtual machine. By submitting a crafted max_encoders value in the migration data, the attacker forces the application to allocate an insufficient amount of memory, resulting in a heap buffer overflow. If successful, this attack could lead to arbitrary code execution within the context of the SPICE server process or induce a denial of service by crashing the virtual machine environment.

## Impact

The vulnerability affects instances using spice-server, common in virtualization environments that provide remote display access to virtual machines. Successful exploitation allows an authenticated client to compromise the underlying virtualization host or service process. This presents a high risk for cloud providers, data centers, and enterprise environments managing virtualized infrastructure, potentially leading to cross-VM data access or service disruption.

## Recommendation

* Monitor virtual machine migration logs for abnormal SPICE protocol traffic.
* Patch the spice-server component to the latest available vendor release addressing CVE-2026-105959.
* Review access controls for SPICE protocol endpoints to ensure only authorized clients can initiate or interact with VM migration sessions.
