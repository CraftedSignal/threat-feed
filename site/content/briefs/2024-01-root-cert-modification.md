---
title: Windows Root Certificate Modification Detection
slug: 2024-01-root-cert-modification
description: The modification of root certificates on Windows systems by unauthorized processes can allow attackers to masquerade malicious files as valid signed components and intercept/decrypt SSL traffic, leading to defense evasion and data collection.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - persistence
  - root certificate
  - mitm
vendors:
  - Microsoft
  - Elastic
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - Sysmon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
references:
  - https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec
  - https://www.ired.team/offensive-security/persistence/t1130-install-root-certificate
rules:
  - title: Detect Root Certificate Modification
    description: Detects the creation or modification of root certificate entries in the Windows registry.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.004
    data_sources:
      - registry_set
      - windows
  - title: Detect Certutil Usage for Certificate Import
    description: Detects the use of certutil.exe to import certificates, which can be used to install malicious root certificates.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1553.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can install malicious root certificates to subvert trust controls and bypass security measures. Once a malicious root certificate is installed, attackers can sign malicious files, making them appear as legitimate software from trusted vendors like Microsoft. This allows the attacker to execute code undetected and maintain persistence on the system. Furthermore, a rogue root certificate can be used in adversary-in-the-middle attacks to decrypt SSL traffic, enabling the collection of sensitive data. This activity is typically achieved through registry modifications. Monitoring for these modifications can help security teams identify potential compromise attempts.

## Attack Chain

1. An attacker gains initial access to a Windows system, possibly through phishing or exploiting a software vulnerability.
2. The attacker elevates privileges to administrator or SYSTEM level, required to modify the trusted root certificate store.
3. The attacker uses tools like certutil.exe or PowerShell to import a malicious root certificate into the Windows registry.
4. The registry keys `HKLM\Software\Microsoft\SystemCertificates\Root\Certificates` or `HKLM\Software\Policies\Microsoft\SystemCertificates\Root\Certificates` are modified to add the new certificate.
5. The attacker uses the newly installed root certificate to sign malicious executables or scripts.
6. The signed malicious files are executed, bypassing signature-based detection mechanisms.
7. The attacker intercepts and decrypts SSL traffic, collecting sensitive data like credentials or financial information.
8. The attacker maintains persistence by using the trusted certificate to repeatedly sign and execute malicious code.

## Impact

Successful installation of a malicious root certificate allows attackers to bypass security controls, leading to the execution of arbitrary code and potential data theft. This can result in significant data breaches, financial losses, and reputational damage. Attackers can use this technique to maintain a long-term presence on compromised systems, making detection and remediation more challenging. While no specific victim counts are available, the technique is broadly applicable across many sectors and can affect any organization running Windows systems.

## Recommendation

*   Deploy the Sigma rule "Detect Root Certificate Modification" to your SIEM to detect registry modifications related to root certificate installation.
*   Enable Sysmon registry event logging to provide the necessary data for the Sigma rule.
*   Investigate any alerts triggered by the Sigma rule, focusing on processes modifying the registry keys related to root certificates.
*   Review the "False Positives" section in the rule documentation to tune the Sigma rule for your environment.
*   Monitor network traffic for suspicious SSL decryption activity following the detection of a root certificate modification.
