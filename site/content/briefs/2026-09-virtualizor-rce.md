---
title: Unauthenticated Remote Command Execution in Softaculous Virtualizor
slug: 2026-09-virtualizor-rce
description: CVE-2026-43641 is an OS command injection vulnerability in the Virtualizor billing module that allows unauthenticated remote attackers to achieve root-level code execution via serialized billing data.
date: "2026-09-22T18:38:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:softaculous:virtualizor:*:*:*:*:*:*:*:*
vendors:
  - Softaculous
products:
  - Virtualizor (< 3.2.9 (Patch 9))
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Softaculous Virtualizor before 3.2.9 (Patch 9) and 3.0.0 contains an OS command injection vulnerability in the billing module handler that allows unauthenticated remote attackers to execute arbitrary commands as root.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: Attackers can deserialize a crafted billing_data POST field and inject shell payloads through the uid field, which is passed unmodified to proc_open() via vexec().
    confidence_band: high
cves:
  - id: CVE-2026-43641
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43641
rules:
  - title: Detects CVE-2026-43641 Exploitation - Command Injection via billing_data
    description: Detects exploitation attempts targeting CVE-2026-43641 by identifying suspicious serialized billing_data containing shell metacharacters in the uid field
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Virtualizor to 3.2.9 (Patch 9) or later.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly names 3.2.9 (Patch 9) as the remediation version
  mitigation_plan:
    - priority: immediate
      action: Patch to 3.2.9 (Patch 9)
      owner: IT Operations
      addresses: CVE-2026-43641
      evidence: NVD remediation advice
---

Softaculous Virtualizor versions prior to 3.2.9 (Patch 9) contain a critical OS command injection vulnerability, tracked as CVE-2026-43641. The vulnerability resides within the application's billing module handler. An unauthenticated remote attacker can bypass existing authentication mechanisms by providing specific, maliciously crafted parameter combinations within a serialized 'billing_data' POST request. 

The injection occurs when the 'uid' field, contained within the deserialized billing data, is passed without adequate sanitization to the application's 'vexec()' function, which subsequently invokes 'proc_open()'. Because the application runs with administrative privileges, successful exploitation grants the attacker root access to the underlying Virtualizor host. This level of access provides complete control over the host server and all virtual private server (VPS) instances managed by the compromised Virtualizor platform. Given the ease of access and the critical severity, organizations using affected versions should prioritize immediate patching.

## Attack Chain

1. The attacker targets an internet-facing Virtualizor instance running a vulnerable version (< 3.2.9).
2. The attacker crafts a malicious HTTP POST request containing a serialized 'billing_data' payload.
3. The payload includes a specially crafted 'uid' parameter containing shell command metacharacters.
4. The Virtualizor billing module deserializes the malicious 'billing_data' input.
5. The application passes the unsanitized 'uid' parameter to the 'vexec()' helper function.
6. The 'vexec()' function passes the input to 'proc_open()', triggering command execution.
7. The system executes the injected commands as the root user.
8. The attacker gains full control over the host and all managed VPS environments.

## Impact

Successful exploitation of CVE-2026-43641 results in total system compromise. An attacker gains root access to the Virtualizor host, enabling them to exfiltrate data, install persistent backdoors, or destroy managed VPS instances. The impact is significant for service providers, as a single compromised Virtualizor host can lead to the widespread breach of multiple downstream client environments hosted on the platform.

## Recommendation

Prioritize the immediate application of the vendor-supplied security update to patch CVE-2026-43641. Upgrade all Virtualizor instances to version 3.2.9 (Patch 9) or later. Configure perimeter firewalls or web application firewalls to inspect and drop incoming POST requests to the billing module that contain unexpected serialized data or suspicious shell-related characters in the 'uid' field. Monitor web server access logs for anomalous POST requests directed at billing endpoints that correlate with the vulnerability patterns identified in this brief.
