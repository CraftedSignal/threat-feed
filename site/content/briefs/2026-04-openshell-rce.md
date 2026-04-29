---
title: OpenShell Arbitrary Code Execution Vulnerability (CVE-2026-41355)
slug: 2026-04-openshell-rce
description: OpenShell before 2026.3.28 is vulnerable to arbitrary code execution via mirror mode when converting untrusted sandbox files into workspace hooks, allowing attackers with mirror mode access to execute code during gateway startup.
date: "2026-04-24T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve
  - rce
  - openshell
vendors:
  - OpenShell
products:
  - OpenShell
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1106
    technique_name: Native API
cves:
  - id: CVE-2026-41355
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41355
  - https://github.com/openclaw/openclaw/commit/c02ee8a3a4cb390b23afdf21317aa8b2096854d1
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-42mx-vp8m-j7qh
  - https://www.vulncheck.com/advisories/openshell-arbitrary-code-execution-via-mirror-mode-sandbox-file-conversion
rules:
  - title: Detect Suspicious OpenShell Mirror Mode
    description: Detects potential exploitation of OpenShell mirror mode vulnerability (CVE-2026-41355) by monitoring for suspicious process creations with specific command-line arguments associated with sandbox file conversion.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious OpenShell Workspace Hook Execution
    description: Detects potential exploitation of OpenShell by looking for process creations spawned by OpenShell with unusual parent processes, indicative of code execution from a workspace hook.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1106
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenShell, a popular start menu replacement for Windows, is vulnerable to arbitrary code execution. Specifically, versions prior to 2026.3.28 are susceptible to CVE-2026-41355, which allows attackers with "mirror mode" access to execute arbitrary code. This vulnerability stems from the insecure conversion of untrusted sandbox files into workspace hooks. An attacker can leverage this flaw to inject malicious code that executes during the OpenShell gateway startup process, gaining control over the host system. This poses a significant risk to systems where OpenShell is used, especially in environments where multiple users or sandboxed applications are present. Successful exploitation allows for complete system compromise.

## Attack Chain

1. Attacker gains low-privilege access to a system with OpenShell installed and "mirror mode" enabled.
2. The attacker crafts a malicious sandbox file containing embedded code.
3. The attacker leverages OpenShell's mirror mode to convert the untrusted sandbox file into a workspace hook.
4. OpenShell improperly handles the conversion, failing to sanitize the malicious code within the workspace hook.
5. The system restarts or the OpenShell gateway service is initialized.
6. During the gateway startup, OpenShell executes the injected malicious code from the compromised workspace hook.
7. The attacker gains arbitrary code execution within the context of the OpenShell process.
8. The attacker escalates privileges or performs other malicious actions, such as installing malware or exfiltrating data.

## Impact

Successful exploitation of CVE-2026-41355 allows an attacker to execute arbitrary code on a vulnerable system. This can lead to complete system compromise, including data theft, malware installation, and denial of service. The vulnerability is particularly dangerous in multi-user environments or systems using sandboxed applications, as it allows attackers to break out of the sandbox and gain control over the host. While the exact number of affected systems is unknown, any system running OpenShell prior to version 2026.3.28 with mirror mode enabled is potentially vulnerable.

## Recommendation

*   Upgrade OpenShell to version 2026.3.28 or later to patch CVE-2026-41355.
*   Disable "mirror mode" in OpenShell if it is not required, reducing the attack surface.
*   Implement the Sigma rule `DetectSuspiciousOpenShellMirrorMode` to detect potential exploitation attempts by monitoring process creations related to OpenShell with specific command-line arguments.
*   Enable process creation logging to activate the `DetectSuspiciousOpenShellMirrorMode` Sigma rule.
