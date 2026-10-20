---
brief_id: brief-2026-02-18-ivanti-epmm-vulns
event_id: brief-2026-02-18-ivanti-epmm-vulns
revision: 2
activity_at: "2026-02-18T06:00:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:b6cd3798ea28099f77af1cf09b8c266265628767a3901a1328ea8667ba9057bc
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Exploitation of Ivanti EPMM Vulnerabilities
slug: 2026-02-18-ivanti-epmm-vulns
description: The Dutch NCSC reported the exploitation of two vulnerabilities in Ivanti EPMM systems as of January 29th, 2026.
date: "2026-02-18T06:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - ivanti
  - epmm
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.003
    technique_name: Web Shell
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
references:
  - https://www.reddit.com/r/blueteamsec/comments/1r7v1bv/ncsc_casus_kwetsbaarheden_ivanti_epmm_systemen/
  - https://www-ncsc-nl.translate.goog/alert/casus-kwetsbaarheden-ivanti-epmm-systemen?_x_tr_sl=nl&_x_tr_tl=en&_x_tr_hl=nl&_x_tr_pto=wapp&_x_tr_hist=true
rules:
  - title: Detect Ivanti EPMM Process Creation by Web Server
    description: Detects processes spawned by the Ivanti EPMM web server that are not typical, indicating potential exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Detect Unauthorized File Modifications in Ivanti EPMM Webroot
    description: Detects file modifications within the Ivanti EPMM webroot directory, which could indicate web shell deployment or other malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
  - title: Detect Outbound Network Connection from Ivanti Tomcat
    description: Detects network connections initiated by Tomcat process (EPMM) to uncommon ports
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 3
---

On January 29th, 2026, the Dutch National Cyber Security Centre (NCSC) discovered active exploitation of two unspecified vulnerabilities within Ivanti Endpoint Manager Mobile (EPMM) systems. The report indicates ongoing exploitation but lacks specific details regarding the threat actor, affected versions, or the precise nature of the vulnerabilities beyond their presence in Ivanti EPMM. This activity poses a significant risk to organizations utilizing Ivanti EPMM for mobile device management, potentially leading to unauthorized access, data breaches, or system compromise. Defenders should prioritize patching and monitoring of Ivanti EPMM deployments.

## Attack Chain

1.  Initial access is gained via exploitation of an unspecified vulnerability in the Ivanti EPMM system, likely through a network-based attack.
2.  The attacker executes arbitrary code on the vulnerable EPMM server.
3.  The attacker establishes a persistent foothold, potentially by creating new user accounts or modifying system configurations.
4.  The attacker performs reconnaissance activities to map out the internal network and identify valuable targets.
5.  The attacker escalates privileges to gain administrative control over the EPMM system and potentially other connected systems.
6.  The attacker exfiltrates sensitive data from the EPMM system, including device configurations, user credentials, and potentially corporate data stored on managed devices.
7.  The attacker may deploy malware to managed mobile devices via the compromised EPMM server.

## Impact

Successful exploitation of Ivanti EPMM vulnerabilities can lead to a range of severe consequences. Organizations could experience data breaches, loss of sensitive information, and potential compromise of managed mobile devices. The lack of specific details in the report makes it difficult to quantify the exact number of victims or the specific sectors targeted. However, given the widespread use of MDM solutions like Ivanti EPMM, a successful attack could have a significant impact on businesses and government organizations alike.
