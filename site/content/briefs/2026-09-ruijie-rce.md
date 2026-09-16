---
title: Remote Command Injection in Ruijie RG-EW3000GX
slug: 2026-09-ruijie-rce
description: A critical remote OS command injection vulnerability in the Ruijie RG-EW3000GX router allows unauthenticated attackers to execute arbitrary commands via the configChange component.
date: "2026-09-16T17:51:03Z"
lastmod: "2026-09-16T17:51:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:h:ruijie:rg-ew3000gx:ew_3.0\(1\)b11p380:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - cve-2026-92398
  - command-injection
vendors:
  - Ruijie
products:
  - RG-EW3000GX (EW_3.0(1)B11P380)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Such manipulation of the argument data.url leads to os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-92397
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92397
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92398
rules:
  - title: Detects CVE-2026-92398 Exploitation - Command Injection via Name Parameter
    description: Detects attempts to exploit CVE-2026-92398 by monitoring for suspicious shell metacharacters in the Name argument sent to the affected path.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
  immediate_actions:
    - action: Restrict external access to administrative management interfaces on Ruijie RG-EW3000GX routers
      owner: SOC
      due: 24h
      evidence: Critical severity vulnerability confirmed via NVD
  mitigation_plan:
    - priority: immediate
      action: Identify and isolate Ruijie RG-EW3000GX routers running version EW_3.0(1)B11P380
      owner: IT Operations
      addresses: CVE-2026-92397
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-09-16T17:51:40Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-92398 Exploitation - Command Injection via Name Parameter'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92398
---

A critical security vulnerability (CVE-2026-92397) has been identified in the Ruijie RG-EW3000GX router, specifically within firmware version EW_3.0(1)B11P380. The vulnerability exists within the 'cc_set' function of the 'unifyframe-sgi.elf' binary, which is part of the 'configChange' component. An attacker can trigger this vulnerability by supplying a malicious payload to the 'data.url' argument. Because the router fails to properly sanitize this input before passing it to the underlying operating system, remote attackers can achieve command injection. This flaw is particularly dangerous as it allows for unauthenticated remote code execution on the networking device, potentially leading to a full compromise of the router, interception of network traffic, or use of the device as a pivot point within the local network. Proof-of-concept exploits have been disclosed publicly, making the risk of exploitation high.

## Attack Chain

1. Attacker performs network reconnaissance to identify exposed management interfaces for Ruijie RG-EW3000GX devices.
2. Attacker crafts an HTTP request targeting the 'configChange' component exposed on the device.
3. Attacker injects a malicious command string into the 'data.url' parameter of the 'cc_set' function call.
4. The web service forwards the unsanitized input to the 'unifyframe-sgi.elf' binary.
5. The binary executes the injected command with the privileges of the web service process.
6. The attacker establishes a reverse shell or downloads additional payloads to maintain persistent access to the device.

## Impact

Successful exploitation of CVE-2026-92397 grants an attacker unauthenticated remote code execution on the target router. Impact includes the ability to bypass network segmentation, perform man-in-the-middle attacks on connected clients, exfiltrate credentials, and utilize the compromised router as a permanent persistence mechanism or bridge into the internal network environment.

## Recommendation

Prioritized actions for security teams:
- Immediately audit perimeter network logs for any HTTP requests containing command injection characters directed at Ruijie RG-EW3000GX devices.
- Patch or update the router firmware to a version beyond EW_3.0(1)B11P380 if available, or restrict access to the device management interface to trusted internal IP ranges only.
- If a patch is unavailable, place affected devices behind a firewall and block external access to administrative endpoints.
