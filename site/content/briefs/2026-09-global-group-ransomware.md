---
title: Global Group Ransomware-as-a-Service Operations
slug: 2026-09-global-group-ransomware
description: The Global Group, a RaaS operation evolved from Black Lock and Mamona, distributes ransomware via phishing-delivered ISO files and legitimate tool abuse to perform double-extortion attacks.
date: "2026-09-22T20:01:41Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Global Group
tags:
  - ransomware
  - phishing
  - double-extortion
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: The ransomware was delivered through an email posing as a Suggested Payment Plan.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204.002
    technique_name: 'User Execution: Malicious File'
    evidence: Upon opening the attached PDF file, a Download button was used as a lure to the recipient.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: Once executed, this file scans the local drivers, network shares, and databases... and runs the cryptographic algorithm to encrypt the data.
    confidence_band: high
references:
  - https://cofense.com/blog/from-payment-plan-to-ransomware-inside-a-global-group-attack
iocs:
  - type: url
    value: https://driverupdate.sbs/access.php
  - type: url
    value: https://globalsupportupdate.top
  - type: hash_sha256
    value: d5004e079cb46db15a7d0b7ecebfa47bb8a1bc19e25749849a017b2a36705260
  - type: hash_md5
    value: 2abd445d3d60fd207b2c62bb0da3a42b
ioc_counts:
  hash_md5: 1
  hash_sha256: 1
  url: 2
rules:
  - title: Detect Suspicious WinMerge Process Activity
    description: Detects potentially malicious use of WinMerge.exe, often used as a loader, when launched with suspicious network connections or from unauthorized paths.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block identified C2 URLs at perimeter security devices.
      owner: SOC
      due: 24h
      evidence: Source provides specific malicious C2 domains.
  hunt_leads:
    - lead: Search for existence of files with '.nZASJgT' extension.
      technique_id: T1486
      data_needed:
        - EDR file system events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Files with .nZASJgT files are specific indicators of compromise.
---

The Global Group is a financially motivated Ransomware-as-a-Service (RaaS) operation that recently emerged as a rebranding of the legacy Black Lock and Mamona ransomware families. By inheriting established backend infrastructure and reusing core code artifacts, the group has quickly scaled its extortion activities. The group primarily targets large-scale enterprises across multiple industries, utilizing "double extortion" tactics where sensitive data is stolen and leaked publicly if ransom demands are not met. They coordinate closely with Initial Access Brokers (IABs) to facilitate network entry. Their delivery method relies on social engineering through phishing emails that pose as "Suggested Payment Plans," leading victims to malicious download sites that serve ISO-based payloads. The operation uses legitimate Windows tools to masquerade malicious activity, effectively bypassing traditional perimeter defenses before deploying encryption toolkits in the C:\Python27.x86 directory.

## Attack Chain

1. Phishing: Attacker sends an email posing as a payment plan, containing a PDF document ("document_989399.pdf").
2. Redirection: The PDF contains a button linking to a malicious site (hXXps://driverupdate[.]sbs/access[.]php) to prompt a file download.
3. Payload Delivery: The victim downloads a malicious ISO file ("Preview-9dc7.iso") containing a shortcut and an executable.
4. Execution: The user runs the executable, which spawns a legitimate process, "WinMerge.exe", to mask subsequent network activity.
5. C2 Communication: The compromised process connects to "hXXps://globalsupportupdate[.]top" to download the primary encryptor ("enc.exe").
6. Persistence/Execution: The encryptor drops toolkit components into "C:\Python27.x86" and initiates a scan of local drivers and network shares.
7. Impact: The ransomware encrypts files using a proprietary cryptographic algorithm and appends the ".nZASJgT" extension.
8. Extortion: The malware changes the desktop wallpaper and drops a "README.nZASJgT.txt" ransom note, initiating business-style negotiations for data recovery and silence.

## Impact

The Global Group ransomware poses a significant threat to global enterprise operations, resulting in the loss of data availability through encryption and the compromise of confidential corporate information via double extortion. By framing negotiations as professional business transactions, the group creates high-pressure environments for victim organizations. Successful attacks result in operational downtime, potential regulatory fines, and reputational damage due to the threat of public data exposure.

## Recommendation

* Deploy the provided Sigma rule to detect the execution of "WinMerge.exe" when initiated from non-standard user profile paths or associated with suspicious network connections.
* Monitor for the creation of files with the ".nZASJgT" extension on local disks and network shares as an early indicator of encryption activity.
* Block the C2 infrastructure domains and URLs identified in the IOC section at the enterprise DNS resolver and proxy.
* Audit for unauthorized file system modifications and directory creation within the "C:\Python27.x86" path.
