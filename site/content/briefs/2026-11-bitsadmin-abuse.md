---
brief_id: brief-2026-11-13-bitsadmin-abuse
event_id: brief-2026-11-13-bitsadmin-abuse
revision: 1
activity_at: "2026-11-13T21:09:55Z"
title: 'Microsoft BITSAdmin: Malicious file transfer abuse'
slug: 2026-11-bitsadmin-abuse
description: Adversaries abuse the legitimate Windows BITSAdmin utility to facilitate file transfers by utilizing /transfer or /addfile commands for downloading payloads.
date: "2026-11-13T21:09:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - bitsadmin
  - living-off-the-land
  - endpoint-security
vendors:
  - Microsoft
products:
  - BITSAdmin
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The following analytic detects BITSAdmin /Transfer or /AddFile commands containing an HTTP or HTTPS URL.
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1197
    technique_name: BITS Jobs
    evidence: The following analytic detects BITSAdmin /Transfer or /AddFile commands containing an HTTP or HTTPS URL and a suspicious transfer characteristic.
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/8eb52117b748d378325f7719554a896e37bccec7/atomics/T1105/T1105.md#atomic-test-9---windows---bitsadmin-bits-download
  - https://github.com/redcanaryco/atomic-red-team/blob/bc705cb7aaa5f26f2d96585fac8e4c7052df0ff9/atomics/T1197/T1197.md
  - https://docs.microsoft.com/en-us/windows/win32/bits/bitsadmin-tool
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/bitsadmin_download_file.yml
rules:
  - title: Detect Suspicious BITSAdmin Download Activity
    description: Detects BITSAdmin /Transfer or /AddFile commands containing an HTTP or HTTPS URL and suspicious transfer characteristics, such as literal IPs, public hosting domains, or suspicious file types in staging directories.
    platform: sigma
    severity: medium
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

BITSAdmin is a built-in Windows command-line tool used to manage Background Intelligent Transfer Service (BITS) jobs. Adversaries may abuse this utility to transfer files using the /transfer or /addfile arguments. Detection of malicious activity requires distinguishing these actions from legitimate software deployment or administrative tasks. A matching command is an indication of a transfer attempt rather than proof of malicious intent.

## Impact
Successful use of BITSAdmin by an adversary can facilitate the download of files to an endpoint, which can be a stage in an attack chain.

## Recommendation
Investigate process ancestry, the remote resource, and destination artifacts when BITSAdmin is invoked. Confirm the job type for /addfile, as it can be used for both download and upload jobs.
