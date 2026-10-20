---
brief_id: brief-2026-10-15-wavlink-rce
event_id: brief-2026-10-15-wavlink-rce
revision: 1
activity_at: "2026-10-15T16:39:28Z"
title: Remote Command Injection in Wavlink WL-WN530BE2-A
slug: 2026-10-wavlink-rce
description: An unauthenticated remote code execution vulnerability (CVE-2026-110957) in the Wavlink WL-WN530BE2-A router allows attackers to inject OS commands via the REMOTE_ADDR parameter in api.cgi.
date: "2026-10-15T16:39:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified against NVD and vendor bulletin.
cpes:
  - cpe:2.3:a:wavlink:wl_wn530be2_a:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - network-security
  - cve-2026-110957
vendors:
  - Wavlink
products:
  - WL-WN530BE2-A (< 2026-09-24-841a51c6d5_tclinux.bin)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to initiate the attack remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The manipulation of the argument REMOTE_ADDR leads to os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-110957
    cvss: 10
    epss: 0.03456
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110957
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade firmware on all affected Wavlink WL-WN530BE2-A routers to 2026-09-24-841a51c6d5_tclinux.bin.
      owner: IT Operations
      due: 24h
      evidence: Vendor confirms that upgrading is sufficient to fix this issue.
  mitigation_plan:
    - priority: immediate
      action: Patch firmware to 2026-09-24-841a51c6d5_tclinux.bin.
      owner: IT Operations
      addresses: CVE-2026-110957
      evidence: Vendor official patch release.
---

CVE-2026-110957 is a critical vulnerability affecting Wavlink WL-WN530BE2-A devices running firmware up to version M30BE2_V250604. The vulnerability exists within the login processing component of the device, specifically in the api.cgi handler. Attackers can leverage improper input validation of the REMOTE_ADDR argument to achieve unauthenticated remote command injection. Because the application historically used the system() function to process login requests, an attacker can supply malicious input that is executed with elevated privileges on the underlying operating system. This vulnerability has been publicly disclosed and is considered exploitable in the wild. Wavlink has released a patch in firmware version 2026-09-24-841a51c6d5_tclinux.bin, which mitigates the issue by replacing the shell-based invocation with a secure argument vector (execvp) and implementing strict input length constraints.

## Impact

The vulnerability carries a CVSS v3.1 base score of 10.0, representing the maximum severity level. Successful exploitation permits an unauthenticated remote attacker to execute arbitrary commands on the router hardware. This can lead to full device compromise, potential participation in botnets, interception of network traffic, and a permanent entry point into the internal network for further lateral movement. Organizations using these devices as perimeter gateways or VPN concentrators are at elevated risk.

## Recommendation

* Immediately upgrade all Wavlink WL-WN530BE2-A routers to firmware version 2026-09-24-841a51c6d5_tclinux.bin or later to address CVE-2026-110957.
* Identify and isolate all internet-facing Wavlink WL-WN530BE2-A devices until firmware updates can be applied.
* Monitor webserver access logs for anomalous HTTP POST requests to api.cgi, specifically looking for shell metacharacters within the REMOTE_ADDR header or query parameters.
