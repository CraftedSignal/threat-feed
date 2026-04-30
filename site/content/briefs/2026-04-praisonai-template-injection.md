---
title: PraisonAI Template Injection Vulnerability (CVE-2026-40154)
slug: 2026-04-praisonai-template-injection
description: PraisonAI before version 4.5.128 is vulnerable to supply chain attacks due to treating remotely fetched template files as trusted executable code without proper verification, enabling exploitation via malicious templates.
date: "2026-04-09T22:16:36Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-40154
  - template-injection
  - supply-chain
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-40154
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40154
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-pv9q-275h-rh7x
iocs:
  - type: email
    value: '[email protected]'
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 2
rules:
  - title: Detect PraisonAI Template File Download
    description: Detects network connections to download template files by PraisonAI, which may indicate an exploitation attempt of CVE-2026-40154.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
  - title: Detect PraisonAI Template File Download Linux
    description: Detects network connections to download template files by PraisonAI on linux systems.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, is susceptible to a critical vulnerability (CVE-2026-40154) affecting versions prior to 4.5.128. The application's design flaw involves treating remotely fetched template files as trusted executable code. This occurs without performing necessary security checks such as integrity verification, origin validation, or user confirmation. This lack of validation opens a significant attack vector, allowing for supply chain compromises. Attackers can inject malicious code into template files, leading to arbitrary code execution within the PraisonAI environment. The vulnerability was reported on April 9, 2026, and patched in version 4.5.128. Defenders should prioritize upgrading to the latest version to mitigate the risk of exploitation via crafted template files.

## Attack Chain

1.  Attacker identifies a PraisonAI instance running a version prior to 4.5.128.
2.  Attacker crafts a malicious template file containing arbitrary code. This could involve injecting shell commands or scripts designed to compromise the system.
3.  The attacker hosts the malicious template file on a remote server under their control.
4.  The attacker manipulates PraisonAI to fetch the malicious template file. This could involve exploiting a configuration setting or tricking a user into initiating the download.
5.  PraisonAI fetches the template file from the attacker's server without proper validation.
6.  The application treats the template file as trusted executable code.
7.  The malicious code within the template is executed by PraisonAI, leading to arbitrary code execution.
8.  The attacker gains unauthorized access to the PraisonAI system and can perform actions such as data exfiltration, lateral movement, or denial of service.

## Impact

Successful exploitation of CVE-2026-40154 can result in a complete compromise of the PraisonAI system. This can lead to unauthorized access to sensitive data, disruption of services, and potential lateral movement within the network. The vulnerable software enables supply chain attacks, making it a critical issue for organizations relying on PraisonAI for their operations. The impact is amplified by the lack of user interaction required for the attack to succeed, with a CVSS v3.1 score of 9.3 highlighting the severity.

## Recommendation

*   Immediately upgrade PraisonAI installations to version 4.5.128 or later to patch CVE-2026-40154.
*   Implement network monitoring to detect attempts to fetch template files from untrusted sources, using the network_connection log source and the IOCs if available.
*   Deploy the Sigma rule "Detect PraisonAI Template File Download" to identify suspicious network connections related to template file retrieval.
*   Implement integrity monitoring on template files if available to detect unauthorized modifications.
