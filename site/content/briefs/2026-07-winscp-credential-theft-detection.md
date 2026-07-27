---
title: Detection of Unauthorized WinSCP Credential Access
slug: 2026-07-winscp-credential-theft-detection
description: This analytic detects unauthorized access to the WinSCP security configuration folder, which stores sensitive SSH and FTP credentials, by processes other than WinSCP, leveraging Windows Security Event 4663 to identify abnormal read or access attempts often indicative of credential-stealing malware like Phantom Stealer.
date: "2026-07-27T18:29:21Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Phantom Stealer
tags:
  - credential-theft
  - infostealer
  - windows
vendors:
  - Martin Prikryl
products:
  - WinSCP
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: WinSCP stores sensitive SSH and FTP session credentials, including passwords and private key references, under the user profile path Martin Prikryl\WinSCP 2\Configuration\Security. Information-stealing malware such as Phantom Stealer targets this directory to harvest stored credentials for exfiltration.
    confidence_band: high
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.phantom_stealer
  - https://www.proofpoint.com/us/blog/threat-insight/not-safe-work-tracking-and-investigating-stealerium-and-phantom-infostealers
iocs:
  - type: url
    value: https://malpedia.caad.fkie.fraunhofer.de/details/win.phantom_stealer
  - type: url
    value: https://www.proofpoint.com/us/blog/threat-insight/not-safe-work-tracking-and-investigating-stealerium-and-phantom-infostealers
ioc_counts:
  url: 2
rules:
  - title: Unauthorized Access to WinSCP Security Configuration
    description: Detects unauthorized access to the WinSCP security configuration folder by processes other than WinSCP itself, indicating potential credential theft by info-stealers like Phantom Stealer. This rule monitors Windows Security Event 4663 (Object Access).
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

This brief details a detection for unauthorized access to WinSCP's security configuration files, a common target for information-stealing malware. WinSCP, a popular free SFTP, SCP, S3, FTP, and WebDAV client for Windows, stores sensitive SSH and FTP session credentials, including plain-text passwords and private key references, within a specific user profile directory: `%APPDATA%\Martin Prikryl\WinSCP 2\Configuration\Security`. Information-stealing malware families, such as Phantom Stealer and Stealerium, specifically target this directory to harvest stored credentials for exfiltration. This detection focuses on identifying any process other than the legitimate WinSCP executable attempting to read or access files within this sensitive configuration path. Such activity is highly anomalous during routine system operation and strongly indicates an attempted credential theft. Defenders should prioritize investigation into any process triggering this alert, including its origin, parent process, and network communications, to mitigate potential unauthorized access to remote systems.

## Attack Chain

1. **Initial Compromise**: A threat actor gains initial access to a victim's Windows endpoint through various means, such as spearphishing, exploiting a vulnerable service, or drive-by download.
2. **Malware Deployment**: The attacker deploys an information-stealing malware, such as Phantom Stealer or Stealerium, to the compromised system.
3. **Credential Harvesting Initialization**: The deployed info-stealer executes, beginning its reconnaissance phase for valuable credentials.
4. **Targeted File Access**: The info-stealer attempts to access files located within the `%APPDATA%\Martin Prikryl\WinSCP 2\Configuration\Security` directory, which is known to contain sensitive WinSCP credentials.
5. **Credential Exfiltration**: The info-stealer reads and parses the WinSCP configuration files, extracting stored SSH and FTP credentials, including passwords and private keys.
6. **Data Transmission**: The harvested credentials are then encoded and exfiltrated to attacker-controlled command and control (C2) infrastructure over various network protocols.
7. **Unauthorized Access**: Threat actors use the stolen credentials to gain unauthorized access to remote systems (e.g., servers, cloud instances) where WinSCP was configured to connect, enabling further lateral movement and data theft.

## Impact

Successful exploitation of this credential theft technique can lead to severe consequences. Attackers can leverage stolen SSH and FTP credentials to gain unauthorized access to critical systems, including production servers, cloud environments, and internal networks. This access can facilitate further lateral movement, data exfiltration of sensitive intellectual property or customer data, deployment of additional malware (e.g., ransomware), and disruption of business operations. The targeted nature of WinSCP credentials implies the attacker is seeking access to specific, often high-value, remote resources configured by the user.

## Recommendation

* **Deploy the Sigma rule** in this brief to your SIEM and tune for your environment.
* **Enable Windows Security Event logging for EventCode 4663** (Object Access) on all endpoints to provide the necessary telemetry for this detection.
* **Investigate any alerts generated by this rule** by examining the `process_name`, `process_path`, and `process_id` fields, along with associated network connections.
* **Review network logs and proxy logs** for connections from the identified suspicious process to external or unusual IP addresses, which may indicate credential exfiltration.
