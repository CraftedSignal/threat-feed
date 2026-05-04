---
title: Remote File Download via Desktopimgdownldr Utility
slug: 2024-01-desktopimgdownldr-remote-file-copy
description: The desktopimgdownldr utility can be abused to download remote files, potentially bypassing standard download restrictions and acting as an alternative to certutil for malware or tool deployment.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - file-download
  - windows
  - desktopimgdownldr
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Elastic Defend
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
rules:
  - title: Remote File Download via Desktopimgdownldr Utility
    description: Detects the use of desktopimgdownldr.exe to download remote files using the /lockscreenurl parameter.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
  - title: Remote File Download via Desktopimgdownldr Utility (Alternate Path)
    description: Detects the use of desktopimgdownldr.exe (from SysWOW64) to download remote files using the /lockscreenurl parameter.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
  - title: Desktopimgdownldr with Encoded URL
    description: Detects desktopimgdownldr.exe using an encoded URL with /lockscreenurl
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

The `desktopimgdownldr.exe` utility, a legitimate Windows tool for configuring lock screen and desktop images, can be misused by adversaries to download arbitrary files from remote locations. This is achieved by leveraging the `/lockscreenurl` argument followed by an HTTP or HTTPS URL. This technique allows attackers to bypass traditional download restrictions and can be used to retrieve malicious payloads, tools, or scripts directly onto a compromised system. This method is particularly effective because `desktopimgdownldr.exe` is a signed Microsoft binary, potentially evading initial detection based on process name or file reputation. The detection rule was initially created in September 2020 and updated in May 2026. This technique is valuable for attackers seeking to transfer files without using common tools like `certutil`, `powershell`, or `bitsadmin`.

## Attack Chain

1.  The attacker gains initial access to the target system through an existing vulnerability, credential compromise, or social engineering.
2.  The attacker executes `desktopimgdownldr.exe` with the `/lockscreenurl` argument, specifying a URL from which to download a malicious file.
3.  `desktopimgdownldr.exe` initiates an HTTP or HTTPS request to the specified URL.
4.  The remote server responds with the file content, which `desktopimgdownldr.exe` saves to disk.
5.  The attacker then executes the downloaded file (e.g., a malicious script or executable).
6.  The malicious code performs actions such as establishing persistence, escalating privileges, or deploying further malware.
7.  The attacker uses the compromised system to move laterally within the network, accessing sensitive data and systems.
8.  The attacker achieves their final objective, such as data exfiltration, ransomware deployment, or disruption of services.

## Impact

Successful exploitation allows attackers to download and execute arbitrary files on a Windows system, leading to potential compromise of the host and the network. This can result in data theft, system damage, or ransomware infection. Due to the legitimate nature of the `desktopimgdownldr.exe` utility, this technique can bypass security controls and detection mechanisms, increasing the likelihood of successful exploitation. While the exact number of victims is unknown, any Windows system where an attacker can execute commands is potentially vulnerable.

## Recommendation

*   Deploy the Sigma rule "Remote File Download via Desktopimgdownldr Utility" to your SIEM to detect the execution of `desktopimgdownldr.exe` with the `/lockscreenurl` argument.
*   Monitor process creation events for `desktopimgdownldr.exe` to identify suspicious command-line arguments.
*   Enable Sysmon process creation logging to ensure sufficient data is available for the provided Sigma rules.
*   Investigate any instances of `desktopimgdownldr.exe` downloading files from external URLs to determine if they are malicious.
*   Implement application control policies to restrict the execution of unauthorized or unknown executables in sensitive environments.
