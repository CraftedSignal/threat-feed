---
title: Arbitrary Code Execution in BusyBox via Heap Buffer Overflow
slug: 2026-09-busybox-rce
description: A heap-based buffer overflow vulnerability (CVE-2022-30065) in BusyBox allows a local attacker to execute arbitrary code and compromise system integrity.
date: "2026-09-16T13:11:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*
  - cpe:2.3:a:busybox:busybox:1.35.0:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:scalance_sc622-2c_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:scalance_sc626-2c_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:scalance_sc632-2c_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:scalance_sc636-2c_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:scalance_sc642-2c_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:scalance_sc646-2c_firmware:*:*:*:*:*:*:*:*
vendors:
  - BusyBox
products:
  - BusyBox (< 1.35.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker with local access can exploit this flaw to execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2022-30065
    cvss: 7.8
    epss: 0.01244
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2023-2115
  - https://nvd.nist.gov/vuln/detail/CVE-2022-30065
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Audit firmware and container images for BusyBox versions older than 1.35.0
      owner: Security Operations
      due: 72h
      evidence: Source documentation of affected versions (< 1.35.0)
  mitigation_plan:
    - priority: immediate
      action: Upgrade BusyBox to version 1.35.0 or higher
      owner: IT Operations
      addresses: CVE-2022-30065
      evidence: Standard security advisory remediation
---

BusyBox, a widely used suite of Unix utilities for embedded Linux systems, contains a heap-based buffer overflow vulnerability identified as CVE-2022-30065. This vulnerability impacts versions of BusyBox prior to 1.35.0. An attacker with local access to a system running an affected version can exploit this flaw to execute arbitrary code. By triggering the buffer overflow during specific command processing operations, an attacker can overwrite memory regions to divert the execution flow of the BusyBox binary. This is particularly critical in embedded environments where BusyBox often runs with elevated privileges or provides essential system administration functions. Defenders should prioritize patching BusyBox in firmware and container images.

## Impact

Successful exploitation of this vulnerability allows a local attacker to achieve arbitrary code execution on the target system. This can lead to full system compromise, unauthorized data access, and disruption of service. Given the prevalence of BusyBox in embedded devices, routers, and minimal Linux environments, the scope of potential impact is significant, particularly in IoT and infrastructure sectors.

## Recommendation

Update BusyBox to version 1.35.0 or later across all firmware, container images, and embedded Linux systems. Monitor for unauthorized or abnormal local process execution patterns using auditd or similar endpoint monitoring tools to detect exploitation attempts that trigger crashes or abnormal utility behavior.
