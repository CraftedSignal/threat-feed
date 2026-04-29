---
title: Unusual Process Loading Mozilla NSS/Mozglue Module
slug: 2024-01-03-unusual-mozglue-load
description: Detection of processes loading Mozilla NSS/Mozglue libraries (mozglue.dll, nss3.dll) outside of known Mozilla applications, potentially indicating malware or unauthorized activity.
date: "2024-01-03T14:30:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - defense-evasion
  - anomaly
  - windows
vendors:
  - Mozilla
  - VMware
  - Dropbox
  - Google
  - Code42
  - Slack
products:
  - Firefox
  - Thunderbird
  - VMware Horizon View Client
  - Dropbox Client
  - Google Earth Pro
  - CrashPlan
  - Pale Moon
  - Waterfox
  - Cyberfox
  - Slack
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://www.trendmicro.com/vinfo/nz/threat-encyclopedia/malware/trojanspy.win32.vidar.yxdftz
rules:
  - title: Unusual Mozilla NSS/Mozglue Module Load by Non-Mozilla Process
    description: Detects processes loading Mozilla NSS/Mozglue libraries outside of known Mozilla applications, indicating potential malware or unauthorized activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218.003
    data_sources:
      - image_load
      - windows
  - title: Suspicious Process Loading NSS3.dll
    description: Detects processes loading NSS3.dll outside of common Mozilla applications. This could be an indicator of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.003
    data_sources:
      - image_load
      - windows
rules_count: 2
---

This brief focuses on detecting anomalous loading of Mozilla NSS (Network Security Services) and Mozglue libraries (specifically `mozglue.dll` and `nss3.dll`) by processes other than known Mozilla applications like Firefox and Thunderbird. The technique leverages Windows Sysmon Event ID 7 (ImageLoaded) to identify such instances. This activity is flagged as suspicious because legitimate software rarely loads these libraries outside of the intended Mozilla ecosystem. Attackers may attempt to load these libraries into other processes to perform malicious actions such as code injection, data exfiltration, or credential theft, while masquerading as legitimate software. This detection is crucial for identifying potentially compromised systems and preventing further damage.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to the system, possibly through phishing, exploiting a vulnerability, or using stolen credentials.
2.  **Persistence:** The attacker establishes persistence on the system, ensuring continued access even after a reboot. This may involve creating scheduled tasks or modifying registry keys.
3.  **Privilege Escalation:** The attacker elevates privileges to gain higher-level access to the system. This can be achieved through exploiting kernel vulnerabilities or misconfigured services.
4.  **Malware Installation:** The attacker deploys malware or malicious tools onto the compromised system. This may involve downloading executables or scripts from a remote server.
5.  **Code Injection:** The attacker injects malicious code into a legitimate process. This is often done to evade detection and execute malicious commands in a trusted context. In this scenario, the injected code might leverage Mozilla NSS/Mozglue libraries.
6.  **Credential Theft:** The injected code attempts to steal credentials stored on the system. This may involve accessing LSASS memory or extracting credentials from web browsers.
7.  **Data Exfiltration:** The attacker exfiltrates sensitive data from the compromised system. This may involve compressing data and transferring it to a remote server using protocols like HTTP or FTP.
8.  **Lateral Movement/Impact:** Using stolen credentials or the compromised system as a pivot, the attacker moves laterally within the network to compromise additional systems, or achieves their ultimate objective, such as ransomware deployment or intellectual property theft.

## Impact

Successful exploitation and anomalous loading of Mozilla libraries can lead to significant damage, including data breaches, financial loss, and reputational damage. Stolen credentials can be used to access sensitive systems and data, while injected code can disrupt critical business processes. The scope can range from individual workstations to entire networks, depending on the attacker's objectives and level of access. The detection helps prevent credential theft, data exfiltration, and lateral movement.

## Recommendation

*   Enable Sysmon Event ID 7 (ImageLoaded) logging on all Windows endpoints to ensure visibility into loaded modules (reference: `data_source`).
*   Deploy the Sigma rule `Unusual Mozilla NSS/Mozglue Module Load by Non-Mozilla Process` to your SIEM and tune the process exceptions for your environment (reference: `rules`).
*   Investigate any instances where Mozilla NSS/Mozglue libraries are loaded by processes not explicitly allowed in the exception list to determine if malicious activity is occurring (reference: `search`).
*   Correlate detections of unusual Mozilla library loading with other suspicious activity, such as network connections to known malicious domains or the execution of unusual processes, to identify potential compromises (reference: `tags`).
*   Review and update the list of legitimate applications that may load Mozilla NSS/Mozglue libraries in your environment to reduce false positives (reference: `known_false_positives`).
