---
title: Spinnaker Clouddriver Pod Remote Code Execution Vulnerability (CVE-2026-32604)
slug: 2026-04-spinnaker-rce
description: Unauthenticated users can execute arbitrary commands on Spinnaker clouddriver pods in vulnerable versions, leading to credential exposure, file deletion, or resource injection.
date: "2026-04-20T21:16:32Z"
severities:
  - critical
tags:
  - cve-2026-32604
  - spinnaker
  - rce
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-32604
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32604
  - https://github.com/spinnaker/spinnaker/releases/tag/spinnaker-release-2025.3.2
  - https://github.com/spinnaker/spinnaker/releases/tag/spinnaker-release-2025.4.2
  - https://github.com/spinnaker/spinnaker/releases/tag/spinnaker-release-2026.0.1
  - https://github.com/spinnaker/spinnaker/security/advisories/GHSA-x3j7-7pgj-h87r
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Process Execution in Spinnaker Clouddriver Pod
    description: Detects suspicious process execution within the Spinnaker clouddriver pod, potentially indicating exploitation of CVE-2026-32604.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Outbound Network Connections from Spinnaker Clouddriver Pod to Non-Standard Ports
    description: Detects suspicious outbound network connections from the Spinnaker clouddriver pod to non-standard ports (excluding 80, 443, 8080, etc.), potentially indicating command and control activity after exploiting CVE-2026-32604.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CVE-2026-32604 describes a critical remote code execution vulnerability affecting Spinnaker, an open-source multi-cloud continuous delivery platform. The vulnerability exists in versions prior to 2026.1.0, 2026.0.1, 2025.4.2, and 2025.3.2. Exploitation allows an attacker to execute arbitrary commands on the clouddriver pods, potentially leading to severe consequences such as credential exposure, unauthorized file removal, and the injection of malicious resources into the environment. Patched…
