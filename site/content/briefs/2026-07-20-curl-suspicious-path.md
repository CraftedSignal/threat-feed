---
title: Windows Curl Download to Suspicious Path Detection
slug: 2026-07-20-curl-suspicious-path
description: This analytic detects the use of Windows Curl.exe to download files to suspicious locations, such as AppData, ProgramData, or Public directories, leveraging Endpoint Detection and Response (EDR) data by focusing on command-line executions that include the -O or --output options; this activity is significant as it can indicate an attempt to bypass security controls or establish persistence, potentially leading to unauthorized code execution, data exfiltration, or further system compromise.
date: "2026-07-24T09:06:10Z"
lastmod: "2026-07-27T18:23:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - endpoint
  - command-and-control
  - defense-evasion
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The following analytic detects the use of Windows Curl.exe to download a file to a suspicious location, such as AppData, ProgramData, or Public directories.
    confidence_band: high
references:
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
  - https://attack.mitre.org/techniques/T1105/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_curl_download_to_suspicious_path.yml
rules:
  - title: Windows Curl Download to Suspicious Path
    description: Detects the use of Windows curl.exe to download files to suspicious locations like AppData, ProgramData, or Public directories, potentially for persistence or defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 1
updates:
  - at: "2026-07-27T18:23:18Z"
    level: L1
    summary: new product
    sources:
      - splunk-escu
    source_urls:
      - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_curl_download_to_suspicious_path.yml
---

This threat brief describes a detection for the use of `curl.exe` on Windows systems to download files into directories commonly abused by attackers for persistence, defense evasion, or temporary storage of malicious payloads. These locations include `AppData`, `ProgramData`, `PerfLogs`, `Windows\Temp`, and `Users\Public`. Attackers leverage the legitimate `curl.exe` utility to retrieve malicious executables, scripts, or other files, often using command-line options like `-O` (output to file) or `--output` to specify a destination path. By placing files in these system or user-specific directories, adversaries attempt to blend in with legitimate system activity, maintain access, or facilitate further stages of an attack. This activity, while sometimes legitimate for administrative tasks, is highly suspicious in typical enterprise environments and warrants investigation due to its potential for leading to unauthorized code execution, data exfiltration, or further system compromise.

## Attack Chain

This brief focuses on a specific detection scenario rather than a multi-stage attack chain, as it targets a common technique used across various campaigns. The observed behavior that triggers this detection is:

1. An attacker executes `curl.exe` on a compromised Windows system, typically via a command prompt, PowerShell, or a malicious script.
2. The `curl.exe` process is initiated with command-line arguments to download a file from a remote source.
3. The command line includes download flags such as `-O`, `--output`, or `--output-dir`.
4. The specified destination for the downloaded file is a suspicious path, such as `C:\ProgramData\`, `C:\Users\<user>\AppData\`, `C:\Users\Public\`, `C:\PerfLogs\`, `C:\Windows\Temp\`, or their respective environment variable equivalents (`%AppData%`, `%Public%`, `%Temp%`).
5. The `curl.exe` process successfully retrieves and saves the remote file to the designated suspicious directory.
6. This action may serve as a precursor to establishing persistence, loading a malicious payload, or further exploiting the system.

## Impact

If this activity is confirmed as malicious, the impact can range from initial compromise leading to unauthorized code execution to more severe outcomes. Successful exploitation often leads to the download and execution of additional malware, such as ransomware, information stealers, or backdoors. This can result in significant data exfiltration, disruption of operations, financial loss, and reputational damage. While the detection itself does not imply immediate compromise, it flags a critical step commonly employed in various attack campaigns (e.g., IcedID, Black Basta, APT37) to deliver payloads and establish a foothold, making early detection crucial.

## Recommendation

* Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
* Enable Sysmon process-creation logging to activate the rule and collect necessary `Image` and `CommandLine` telemetry.
* Configure Windows Event Log Security (Event ID 4688) for process creation with command-line auditing to provide the required data for the rule.
* Review network egress logs for `curl.exe` making outbound connections to unusual or suspicious domains, especially when combined with suspicious file writes.
