---
title: GhostLock Tool Abuses Windows API to Block File Access
slug: 2026-05-ghostlock-file-access-abuse
description: GhostLock is a proof-of-concept tool that abuses the Windows CreateFileW API to block access to files on local and SMB network shares, causing a denial-of-service condition.
date: "2026-05-11T22:03:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - windows
  - file-access
vendors:
  - Microsoft
products:
  - Windows
  - SMB network shares
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://www.bleepingcomputer.com/news/security/new-ghostlock-tool-abuses-windows-api-to-block-file-access/
rules:
  - title: Detect High Volume of File Open Requests with Exclusive Access
    description: Detects processes rapidly opening files with exclusive access (dwShareMode = 0), indicative of GhostLock activity.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
  - title: Detect CreateFileW API calls with dwShareMode = 0
    description: Detects calls to the CreateFileW API with the dwShareMode parameter set to 0, indicating an attempt to gain exclusive access to a file.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - image_load
      - windows
rules_count: 2
---

The GhostLock tool, developed by Kim Dvash of Israel Aerospace Industries, is a proof-of-concept demonstrating how the Windows `CreateFileW` API can be abused to create a denial-of-service condition. The technique exploits the `dwShareMode` parameter of the `CreateFileW` function to open files in exclusive mode, preventing other users and applications from accessing them. The GhostLock tool automates this by recursively opening a large number of files on SMB shares. While GhostLock is active, attempts to access those files result in a sharing violation error. This attack can be launched by standard domain users without elevated privileges. While primarily a disruption technique, GhostLock could be used as a decoy during intrusions to distract IT staff during data theft or lateral movement.

## Attack Chain

1.  An attacker compromises a system on the network.
2.  The attacker executes the GhostLock tool.
3.  GhostLock uses the `CreateFileW` API to recursively open files on local or SMB network shares.
4.  The `dwShareMode` parameter is set to 0, granting exclusive access to the opened files.
5.  Windows grants the GhostLock process exclusive access, preventing other users or applications from opening the same files.
6.  Legitimate users attempting to access the files receive a "STATUS_SHARING_VIOLATION" error.
7.  The attacker maintains the open file handles to sustain the denial-of-service condition.
8.  The disruption hinders normal business operations, potentially masking other malicious activities like data exfiltration.

## Impact

The GhostLock tool causes a denial-of-service condition by preventing legitimate users and applications from accessing files stored locally or on SMB network shares. Although not destructive like ransomware, the attack can lead to significant operational downtime. The attack could also be used as a diversionary tactic to mask other malicious activities, such as data theft or lateral movement within the network. The impact is primarily disruption-based.

## Recommendation

*   Monitor per-session open-file counts with `ShareAccess = 0` at the file server layer, as recommended by the researcher. This metric is found in storage platform management interfaces, not Windows event logs or EDR telemetry.
*   Deploy the Sigma rule below to detect processes making a large number of file open requests with `ShareAccess = 0`. Tune the threshold for your environment.
*   Implement the NDR detection rule outlined in the GhostLock whitepaper, available from the researcher, to identify anomalous file access patterns.
