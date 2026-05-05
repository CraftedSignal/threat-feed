---
title: Windows Universal Data Link File Creation Detection
slug: 2024-01-udl-file-creation
description: The creation of Universal Data Link (UDL) files on Windows systems can indicate a phishing technique where attackers bypass email filters and capture user credentials by tricking victims into testing a connection to a malicious server.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - phishing
  - credential-theft
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
references:
  - https://trustedsec.com/blog/oops-i-udld-it-again
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_universal_data_link_file_creation.yml
rules:
  - title: Detect UDL File Creation
    description: Detects the creation of Universal Data Link (UDL) files, which can be indicative of a phishing attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1204.002
      - T1566.001
    data_sources:
      - file_event
      - windows
  - title: Detect UDL File Creation with Suspicious Process
    description: Detects the creation of Universal Data Link (UDL) files by a process other than explorer.exe, cmd.exe or powershell.exe
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1204.002
      - T1566.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Attackers are increasingly using Universal Data Link (UDL) files as part of phishing campaigns. These files, typically used in Windows for database connections, can be exploited to bypass email filters. By tricking victims into opening these specially crafted UDL files, attackers can prompt the system to connect to a malicious server, potentially capturing user credentials or other sensitive information. This technique has been observed to successfully evade traditional security measures, making it crucial for defenders to monitor for UDL file creation events. The use of UDL files in this manner allows for a stealthier approach compared to traditional phishing attachments.

## Attack Chain

1. The attacker crafts a malicious UDL file designed to connect to a rogue database server.
2. The attacker sends a phishing email containing the malicious UDL file as an attachment.
3. The victim receives the email and, through social engineering, is convinced to open the UDL file.
4. Upon opening, the UDL file attempts to establish a connection to the attacker's controlled server, as defined in the file's connection string.
5. The victim's system may prompt for credentials if the connection string requires authentication.
6. If the victim enters credentials, they are sent to the attacker's server.
7. The attacker captures the credentials and uses them for unauthorized access to sensitive systems or data.

## Impact

Successful exploitation can lead to credential theft, potentially granting attackers access to sensitive databases, internal systems, and user accounts. The number of victims depends on the scale of the phishing campaign, but even a small number of compromised accounts can lead to significant data breaches or system compromise. Sectors commonly targeted by phishing attacks include finance, healthcare, and government, where access to data is highly valuable.

## Recommendation

*   Deploy the Sigma rule `Detect UDL File Creation` to your SIEM and tune for your environment to detect the creation of UDL files.
*   Enable Sysmon Event ID 11 logging to ensure the necessary data is captured for the detection rule.
*   Educate users about the risks associated with opening UDL files from untrusted sources to prevent social engineering attacks.
