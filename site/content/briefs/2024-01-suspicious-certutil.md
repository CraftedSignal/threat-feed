---
title: Suspicious CertUtil Commands Used for Defense Evasion
slug: 2024-01-suspicious-certutil
description: Attackers abuse certutil.exe, a native Windows utility, to download/deobfuscate malware for command and control or data exfiltration, evading defenses.
date: "2024-01-03T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - command-and-control
  - credential-access
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1140
    technique_name: Deobfuscate/Decode Files or Information
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://twitter.com/Moriarty_Meng/status/984380793383370752
  - https://twitter.com/egre55/status/1087685529016193025
  - https://www.sysadmins.lv/blog-en/certutil-tips-and-tricks-working-with-x509-file-format.aspx
  - https://docs.microsoft.com/en-us/archive/blogs/pki/basic-crl-checking-with-certutil
  - https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry
rules:
  - title: Suspicious CertUtil Usage for Encoding/Decoding
    description: Detects suspicious use of certutil.exe to encode or decode files, which is often used to obfuscate malicious payloads.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1140
    data_sources:
      - process_creation
      - windows
  - title: Suspicious CertUtil URL Download
    description: Detects certutil.exe being used to download files from URLs, which is often a sign of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CertUtil is a command-line utility included with Windows, designed for managing digital certificates and certificate services. Attackers frequently abuse it to "live off the land" by downloading malware, deobfuscating files, and establishing command and control channels within compromised environments. This activity leverages certutil.exe to perform actions typically associated with malicious payloads, blending in with legitimate system activity and evading traditional security measures. The tool's capability to encode, decode, and retrieve files from URLs makes it a versatile asset for attackers aiming to maintain a low profile while executing malicious operations. This detection focuses on identifying specific command-line arguments indicative of this abuse, such as those used for encoding, decoding, and URL retrieval.

## Attack Chain

1.  The attacker gains initial access through an undisclosed means (e.g., phishing, exploit).
2.  The attacker executes certutil.exe via cmd.exe or PowerShell.
3.  Certutil is used with the `urlcache` parameter to download a malicious payload from a remote server.
4.  Certutil uses the `decode` parameter to decode a base64-encoded payload, saving it to disk.
5.  The attacker uses certutil with `encodehex` to encode a binary into a hexadecimal representation to evade signature-based detection.
6.  The attacker then uses certutil with `decodehex` to decode the hexadecimal encoded data.
7.  The attacker executes the decoded payload, gaining further control of the system.
8.  The attacker establishes a command and control channel, using certutil to encode/decode communications.

## Impact

Successful exploitation allows attackers to download and execute arbitrary code, bypass security measures, and maintain persistence within the compromised system. This can lead to data exfiltration, system compromise, and further propagation of the attack within the network. The lack of directly observed IOCs in the originating advisory limits quantification of victim count and impact scope, but the technique is widely applicable.

## Recommendation

*   Deploy the Sigma rule "Suspicious CertUtil Usage for Encoding/Decoding" to detect abuse of encoding/decoding functions within certutil.exe, focusing on unusual file types or destinations.
*   Deploy the Sigma rule "Suspicious CertUtil URL Download" to identify certutil.exe being used to download files from URLs, and tune the rule based on known good software deployment practices.
*   Enable Sysmon process creation logging to ensure the rules above function correctly by capturing command-line arguments (as referenced in the logsource for each rule).
*   Review historical process execution logs for instances of certutil.exe using suspicious parameters like `decode`, `encode`, `urlcache`, `verifyctl`, `encodehex`, `decodehex`, or `exportPFX` to identify potentially compromised systems.
