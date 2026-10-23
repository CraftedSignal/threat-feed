---
brief_id: brief-2026-10-ahsay-cbs-rce
event_id: brief-2026-10-ahsay-cbs-rce
revision: 7
activity_at: "2026-10-23T17:44:45Z"
revision_history:
  - revision: 2
    at: "2026-10-23T09:22:30Z"
    checksum: sha256:00eed54739bac0b9df71694f998416e941aef281ba9944fa04b33b9177ce48bd
    summary: new product
    changed_fields:
      - cpes
      - cves
      - lastmod
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/ahsay-ahsaycbs-cve-2026-105134
  - revision: 3
    at: "2026-10-23T11:27:22Z"
    checksum: sha256:bf5582148055f9e0fb2f1f41f9af9f69f4d1b0a5ef6b3da9b155701f3e2b0323
    summary: new product
    changed_fields:
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/ahsay-ahsaycbs-cve-2026-105134
  - revision: 4
    at: "2026-10-23T14:34:49Z"
    checksum: sha256:e236bc11c3454686cb8c087402c713f1bbbf82f243e8b65f083c63ed71392555
    summary: new product
    changed_fields:
      - cves
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/ahsay-ahsaycbs-cve-2026-105134
  - revision: 5
    at: "2026-10-23T15:41:17Z"
    checksum: sha256:74b370ffecfb2af938a7f651ae7777633908be493528df971c76251c1021d91a
    summary: new product
    changed_fields:
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/ahsay-ahsaycbs-cve-2026-105134
  - revision: 6
    at: "2026-10-23T16:39:11Z"
    checksum: sha256:18eaaf3e06c80d68c1181245ae249ac3daf35b63d07e4daef30754dbdbdabf1d
    summary: new product
    changed_fields:
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/ahsay-ahsaycbs-cve-2026-105134
  - revision: 7
    at: "2026-10-23T17:44:45Z"
    checksum: sha256:a9a568ae260b03e96f32020ff593a0092af5ea2881ad4f29d165655e1a62e271
    summary: new product
    changed_fields:
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/ahsay-ahsaycbs-cve-2026-105134
title: Unauthenticated Remote Code Execution in Ahsay AhsayCBS
slug: 2026-10-ahsay-cbs-rce
description: Ahsay AhsayCBS up to version 10.3.2 is vulnerable to unauthenticated remote OS command injection via the /rps/api/json/UpdateReceivers.do endpoint, enabling full system compromise.
date: "2026-10-04T09:01:29Z"
lastmod: "2026-10-23T17:44:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation in lab
cpes:
  - cpe:2.3:a:ahsay:ahsaycbs:*:*:*:*:*:*:*:*
  - cpe:2.3:a:ahsay:cloud_backup_suite:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=01552F8F-EE68-5958-8B08-C7BF7F992387&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - authentication-bypass
  - remote-access
vendors:
  - Ahsay
  - Ahsay Systems
products:
  - AhsayCBS (< 10.3.4)
  - AhsayCBS (<= 10.3.2)
  - AhsayCBS (<= 10.3.4)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This vulnerability affects unknown code of the file /rps/api/json/UpdateReceivers.do of the component Replication Receiver. It is possible to launch the attack remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Executing a manipulation of the argument random can lead to os command injection.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Performing a manipulation of the argument random results in improper authentication.
    confidence_band: high
cves:
  - id: CVE-2026-105134
    cvss: 10
    epss: 0.3831
    kev_status: "false"
  - id: CVE-2026-105133
    cvss: 7.3
    epss: 0.05794
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105134
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105133
  - https://sploitus.com/exploit?id=01552F8F-EE68-5958-8B08-C7BF7F992387&utm_source=rss&utm_medium=rss
  - https://www.securityweek.com/unpatched-ahsaycbs-vulnerabilities-exploited-in-the-wild/
  - https://pwn.watch/i/ahsay-ahsaycbs-cve-2026-105134
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
rules:
  - title: Detects CVE-2026-105134 Exploitation - Unauthenticated RCE via /rps/api/json/UpdateReceivers.do
    description: Detects exploitation attempts against CVE-2026-105134 by identifying suspicious command injection patterns in the 'random' parameter of the UpdateReceivers.do endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade AhsayCBS to 10.3.4
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 10.3.4 is able to resolve this issue.
  mitigation_plan:
    - priority: immediate
      action: Patch AhsayCBS to 10.3.4
      owner: IT Operations
      addresses: CVE-2026-105134
      evidence: Upgrading to version 10.3.4 is able to resolve this issue.
updates:
  - at: "2026-10-23T11:26:27Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/ahsay-ahsaycbs-cve-2026-105134
  - at: "2026-10-23T14:33:55Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/ahsay-ahsaycbs-cve-2026-105134
  - at: "2026-10-23T15:40:23Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/ahsay-ahsaycbs-cve-2026-105134
  - at: "2026-10-23T16:38:37Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/ahsay-ahsaycbs-cve-2026-105134
  - at: "2026-10-23T17:44:05Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/ahsay-ahsaycbs-cve-2026-105134
---

Ahsay AhsayCBS, a backup software solution, contains a critical security vulnerability (CVE-2026-105134) in the Replication Receiver component. The flaw exists within the /rps/api/json/UpdateReceivers.do endpoint, where the 'random' argument is processed in an insecure manner. An unauthenticated remote attacker can inject arbitrary OS commands by manipulating this argument, leading to complete unauthorized access and execution of code with the privileges of the AhsayCBS application. With a CVSS base score of 10.0, this vulnerability poses a severe risk to organizations using the affected software. Publicly available exploit code has been reported, significantly increasing the likelihood of exploitation. Administrators must upgrade to version 10.3.4 immediately to remediate the vulnerability.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to execute arbitrary system commands, leading to full server compromise, data exfiltration, or deployment of additional malicious payloads such as ransomware. The impact is critical, affecting any environment where AhsayCBS is exposed to the network.

## Recommendation

- Upgrade all instances of AhsayCBS to version 10.3.4 or later immediately.
- Apply the rules below to identify exploitation attempts targeting the identified API endpoint.
- Restrict network access to the AhsayCBS management interface to trusted IP addresses only, especially for the Replication Receiver component.
