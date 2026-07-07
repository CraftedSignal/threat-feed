---
title: Data Exfiltration via Curl to File-Sharing Websites
slug: 2026-07-curl-file-upload-exfiltration
description: This brief details the use of `curl.exe` by an attacker on a compromised Windows host to exfiltrate sensitive data to public file-sharing services, leading to potential data loss and regulatory non-compliance.
date: "2026-07-03T15:11:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - data-exfiltration
  - utility
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Detects usage of curl to upload files to known file sharing domains, which may indicate data exfiltration.
    confidence_band: high
references:
  - https://unit42.paloaltonetworks.com/advanced-backdoor-squidoor/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_curl_upload_file_sharing_websites.yml
rules:
  - title: Curl File Upload To File Sharing Websites
    description: Detects usage of `curl.exe` to upload files to known public file-sharing domains, which may indicate data exfiltration from a compromised Windows host.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This threat brief focuses on the post-compromise activity of data exfiltration using the legitimate `curl.exe` utility to upload files to public file-sharing websites. While `curl` is a standard utility, its use in conjunction with specific command-line arguments and known file-sharing domains (such as `wetransfer.com`, `transfer.sh`, `file.io`, and `pastebin`) is a strong indicator of malicious intent. Threat actors frequently leverage such methods to bypass traditional network defenses and move stolen data out of compromised environments. This activity is critical for defenders to detect as it signifies a successful breach that has progressed to the data exfiltration stage, potentially leading to significant data loss, intellectual property theft, and severe reputational and financial damage.

## Attack Chain

1.  Following initial compromise and potentially internal reconnaissance, the attacker identifies sensitive data on the Windows host.
2.  The attacker prepares the target data for exfiltration, which may involve compression or encryption, and stages it for transfer.
3.  The attacker executes `curl.exe` from a command prompt or script on the compromised host.
4.  The `curl.exe` command includes specific flags such as `--form`, `--upload-file`, `--data`, `-X POST`, `-sT`, or `-d` to initiate a file upload.
5.  The command specifies a known public file-sharing domain (e.g., `0x0.st`, `bashupload.com`, `wetransfer.com`) as the destination for the uploaded file.
6.  `curl.exe` establishes an outbound network connection to the file-sharing service and transmits the specified sensitive data from the compromised system.
7.  Upon successful upload, the attacker retrieves the exfiltrated data from the public file-sharing service using the provided download link, completing the data theft.

## Impact

The successful exfiltration of data using this method can have severe consequences for an organization. This typically results in significant data loss, including sensitive intellectual property, customer data, or regulated personal identifiable information (PII). Such incidents can lead to substantial financial penalties due to regulatory non-compliance (e.g., GDPR, CCPA), loss of customer trust, and long-term reputational damage. Depending on the data's sensitivity, the breach could also empower competitors, disrupt business operations, or facilitate further attacks.

## Recommendation

*   Deploy the Sigma rule "Curl File Upload To File Sharing Websites" provided in this brief to your SIEM/EDR to detect suspicious `curl.exe` activity targeting public file-sharing sites.
*   Ensure Sysmon process-creation logging is enabled on all Windows endpoints to capture command-line arguments of executed processes, which is crucial for activating the rule.
*   Review network egress logs for connections to the domains listed in the `selection_cli_domain` of the Sigma rule to identify unapproved data transfers.
*   Implement data loss prevention (DLP) solutions to monitor and block uploads of sensitive information to unapproved cloud storage or file-sharing services.
