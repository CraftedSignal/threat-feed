---
title: Nx Console Compromised Extension Harvesting Credentials (CVE-2026-48027)
slug: 2026-05-nx-console-credential-harvesting
description: Nx Console contained an embedded malicious code vulnerability (CVE-2026-48027) which allowed a malicious version of the extension to be published and harvest credentials from disk and memory.
date: "2026-05-27T17:41:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - credential-theft
  - cve
vendors:
  - Nx
products:
  - Nx Console
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-48027
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-48027
  - https://github.com/nrwl/nx-console/security/advisories/GHSA-c9j4-9m59-847w
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48027
rules:
  - title: Detect Suspicious Outbound Connection from VSCode Extension
    description: Detects suspicious outbound network connections initiated by VS Code extensions, potentially indicating data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
  - title: Detect Credential Harvesting via File System Scan by VSCode
    description: Detects unusual process access events where VSCode scans for sensitive file types, which is an indicator of credential harvesting
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Nx Console, a popular extension, was compromised when a malicious version was published containing embedded malicious code. This vulnerability, identified as CVE-2026-48027, enabled the compromised extension to fetch an obfuscated payload. This payload was designed to harvest credentials from various sources, including both on-disk locations and in-memory storage. The incident highlights the supply chain risks associated with software extensions and the potential for credential theft when such extensions are compromised. Defenders should apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

## Attack Chain

1. A developer installs the legitimate Nx Console extension from the marketplace.
2. The attacker publishes a malicious version of the Nx Console extension, exploiting CVE-2026-48027.
3. The developer's IDE automatically updates to the malicious version of the extension.
4. The malicious extension executes and fetches an obfuscated payload from a remote server.
5. The obfuscated payload is executed within the context of the IDE.
6. The payload begins scanning the file system for common credential storage locations (e.g., .env files, configuration files).
7. The payload also attempts to extract credentials from the IDE's memory space, potentially targeting stored API keys and tokens.
8. The harvested credentials are exfiltrated to a remote server controlled by the attacker, potentially leading to unauthorized access to sensitive systems and data.

## Impact

The compromise of the Nx Console extension led to the potential harvesting of credentials from developers' machines. The number of affected users is currently unknown. Successful exploitation could lead to unauthorized access to source code repositories, cloud infrastructure, and other sensitive resources. The open-source component, third-party library, protocol, or proprietary implementation could be used by different products, expanding the scope of the impact.

## Recommendation

*   Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable as outlined in the advisory.
*   Monitor network connections originating from IDE processes for suspicious outbound traffic, which may indicate exfiltration attempts as part of the attack chain.
*   Implement the Sigma rule "Detect Suspicious Outbound Connection from VSCode Extension" to detect potential data exfiltration from VSCode extensions.
*   Enable process monitoring and audit logging to detect the execution of unusual or obfuscated payloads within the IDE context.
