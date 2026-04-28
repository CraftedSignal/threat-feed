---
title: Spinnaker Clouddriver Pod Remote Code Execution Vulnerability (CVE-2026-32604)
slug: 2026-04-spinnaker-rce
description: Unauthenticated users can execute arbitrary commands on Spinnaker clouddriver pods in vulnerable versions, leading to credential exposure, file deletion, or resource injection.
date: "2026-04-20T21:16:32Z"
type: coverage
types:
  - coverage
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
iocs:
  - type: email
    value: '[email&#160;protected]'
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

CVE-2026-32604 describes a critical remote code execution vulnerability affecting Spinnaker, an open-source multi-cloud continuous delivery platform. The vulnerability exists in versions prior to 2026.1.0, 2026.0.1, 2025.4.2, and 2025.3.2. Exploitation allows an attacker to execute arbitrary commands on the clouddriver pods, potentially leading to severe consequences such as credential exposure, unauthorized file removal, and the injection of malicious resources into the environment. Patched versions are available (2026.1.0, 2026.0.1, 2025.4.2, and 2025.3.2). A temporary mitigation involves disabling the gitrepo artifact types. This vulnerability poses a significant risk to organizations using vulnerable Spinnaker instances, potentially enabling attackers to compromise their continuous delivery pipelines and underlying cloud infrastructure.

## Attack Chain

1.  An attacker sends a crafted request to the Spinnaker clouddriver service, exploiting the vulnerability in handling gitrepo artifacts.
2.  The clouddriver service processes the malicious request without proper input validation.
3.  The lack of input validation allows the attacker to inject arbitrary commands into the system.
4.  The injected commands are executed within the context of the clouddriver pod.
5.  The attacker leverages the command execution to access sensitive information, such as credentials stored within the pod's environment or configuration files.
6.  The attacker may further use the command execution to remove critical system files, disrupting the functionality of the Spinnaker instance.
7.  Alternatively, the attacker could inject malicious resources, such as backdoors or reverse shells, into the system to establish persistent access.
8.  The attacker achieves full control of the clouddriver pod, enabling them to compromise the continuous delivery pipeline and potentially pivot to other systems within the cloud environment.

## Impact

Successful exploitation of CVE-2026-32604 allows an attacker to execute arbitrary commands on Spinnaker clouddriver pods. This can lead to the exposure of sensitive credentials, potentially compromising access to other cloud services and infrastructure. Attackers could also remove critical files, disrupting the continuous delivery process, or inject malicious resources to maintain persistent access and potentially compromise the entire software supply chain. The severity of the impact depends on the specific environment and the level of access granted to the Spinnaker instance, but a successful exploit can result in a full system compromise and significant operational disruption.

## Recommendation

*   Upgrade Spinnaker instances to versions 2026.1.0, 2026.0.1, 2025.4.2, or 2025.3.2 to patch CVE-2026-32604.
*   As a temporary workaround, disable the gitrepo artifact types in Spinnaker configurations until the upgrade can be performed.
*   Monitor web server logs for suspicious requests targeting the Spinnaker clouddriver service (cs-uri-query, cs-method) to detect potential exploitation attempts.
*   Implement network segmentation to limit the blast radius of a potential compromise of the clouddriver pods, restricting lateral movement to other critical systems.
*   Monitor process creation events within the clouddriver pods for unexpected or unauthorized commands being executed. Use the process creation rule provided.
