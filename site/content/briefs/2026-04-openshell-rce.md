---
title: OpenShell Arbitrary Code Execution Vulnerability (CVE-2026-41355)
slug: 2026-04-openshell-rce
description: OpenShell before 2026.3.28 is vulnerable to arbitrary code execution via mirror mode when converting untrusted sandbox files into workspace hooks, allowing attackers with mirror mode access to execute code during gateway startup.
date: "2026-04-24T12:00:00Z"
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

OpenShell, a popular start menu replacement for Windows, is vulnerable to arbitrary code execution. Specifically, versions prior to 2026.3.28 are susceptible to CVE-2026-41355, which allows attackers with "mirror mode" access to execute arbitrary code. This vulnerability stems from the insecure conversion of untrusted sandbox files into workspace hooks. An attacker can leverage this flaw to inject malicious code that executes during the OpenShell gateway startup process, gaining control over…
