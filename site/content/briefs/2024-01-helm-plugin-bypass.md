---
title: Helm Plugin Verification Bypass Vulnerability
slug: 2024-01-helm-plugin-bypass
description: Helm versions 4.0.0 through 4.1.3 fail to enforce plugin signature verification when the .prov file is missing, allowing installation of unsigned plugins and potentially leading to arbitrary code execution.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - helm
  - kubernetes
  - plugin
  - signature-bypass
  - cve-2026-35205
vendors:
  - Helm
products:
  - Helm
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35205
    epss: 0.00014
references:
  - https://github.com/advisories/GHSA-q5jf-9vfq-h4h7
rules:
  - title: Detect Helm Plugin Installation Without Provenance
    description: Detects Helm plugin installations where the .prov file is missing, indicating a potential signature verification bypass.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1608
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Process Execution from Helm Plugin Directory
    description: Detects suspicious process execution from within a Helm plugin directory.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Helm is a package manager for Kubernetes. A vulnerability exists in Helm versions 4.0.0 through 4.1.3 where the platform fails to verify plugin signatures if the `.prov` file is missing during plugin installation or update. This bypass allows malicious plugin authors to omit provenance data, circumventing the intended signature verification process. Successful exploitation enables the installation of unsigned plugins, which can then execute arbitrary code via plugin hooks. This is a significant concern for Kubernetes environments relying on Helm for package management and plugin security. The issue was patched in Helm v4.1.4.

## Attack Chain

1. An attacker crafts a malicious Helm plugin, omitting the `.prov` file to bypass signature verification.
2. The attacker distributes the malicious plugin through a compromised repository or social engineering.
3. A user attempts to install or update the plugin using `helm plugin install` or `helm plugin update`.
4. Due to the missing `.prov` file, Helm versions 4.0.0-4.1.3 skip signature verification.
5. The malicious plugin is installed successfully, despite lacking a valid signature.
6. The user interacts with the installed plugin or a Helm hook triggers execution of the plugin's code.
7. The malicious plugin executes arbitrary code on the Kubernetes cluster or the user's machine.
8. The attacker gains unauthorized access or control over the system, potentially leading to data exfiltration, resource compromise, or denial of service.

## Impact

Successful exploitation of this vulnerability can lead to arbitrary code execution within a Kubernetes environment. The impact could range from data exfiltration and resource hijacking to complete compromise of the cluster. Given the widespread adoption of Helm in managing Kubernetes applications, a significant number of organizations are potentially vulnerable. The vulnerability affects versions 4.0.0 through 4.1.3, requiring users to upgrade to version 4.1.4 or later to mitigate the risk.

## Recommendation

*   Upgrade Helm to version 4.1.4 or later to patch CVE-2026-35205.
*   Implement manual validation that a plugin archive contains provenance data (`.prov` file) before installation as a short-term workaround.
*   Deploy the Sigma rule "Detect Helm Plugin Installation Without Provenance" to identify attempts to install plugins without `.prov` files.
*   Monitor Helm plugin installation events for unexpected processes or network connections originating from plugin directories using the "Suspicious Process Execution from Helm Plugin Directory" Sigma rule.
