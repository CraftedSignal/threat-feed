---
brief_id: brief-2026-10-28-automatic-translation-rce
event_id: brief-2026-10-28-automatic-translation-rce
revision: 1
activity_at: "2026-10-28T19:23:49Z"
title: 'Automatic Translation WordPress Plugin: Unauthenticated Remote Code Execution (CVE-2024-50493)'
slug: 2026-10-automatic-translation-rce
description: An unauthenticated arbitrary file upload vulnerability in the Automatic Translation WordPress plugin (versions 1.0.4 and below) allows remote attackers to upload arbitrary files via the /wp-json/automatic-translator/v1/saveDoc endpoint to achieve remote code execution.
date: "2026-10-28T19:23:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Awaiting environment validation.
products:
  - Automatic Translation (<= 1.0.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated arbitrary file upload due to missing file type validation in Automatic Translation <= 1.0.4, enabling upload of arbitrary files.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2024-50493
    cvss: 10
    epss: 0.01063
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-RANDOMROBBIEBF-CVE-2024-50493
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-RANDOMROBBIEBF-CVE-2024-50493&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2024-50493 Exploitation - Unauthenticated File Upload to Automatic Translation
    description: Detects exploitation attempts against CVE-2024-50493 by monitoring for POST requests to the vulnerable saveDoc API endpoint.
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
    - action: Inventory WordPress sites for 'Automatic Translation' plugin
      owner: IT Operations
      due: 24h
      evidence: Plugin identified as vulnerable in source.
  hunt_leads:
    - lead: Search web logs for POST requests to /wp-json/automatic-translator/v1/saveDoc
      technique_id: T1190
      data_needed:
        - Web access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source provides explicit path and method for exploitation.
  mitigation_plan:
    - priority: immediate
      action: Disable or remove Automatic Translation plugin
      owner: IT Operations
      addresses: CVE-2024-50493
      evidence: Plugin version <= 1.0.4 is confirmed vulnerable.
---

The Automatic Translation WordPress plugin is vulnerable to an unauthenticated arbitrary file upload flaw due to the lack of file type validation in versions 1.0.4 and earlier. The vulnerability resides in the /wp-json/automatic-translator/v1/saveDoc API endpoint. An attacker can use this flaw to upload arbitrary files, such as PHP web shells, to the web server, leading to potential remote code execution. A functional exploit proof-of-concept (PoC) has been publicly released.

## Impact

Successful exploitation allows an unauthenticated, remote attacker to execute arbitrary code on the target web server with the privileges of the web application service. This can lead to full server compromise, data exfiltration, and lateral movement within the hosting environment.

## Recommendation

* Identify and audit all WordPress installations for the presence of the 'Automatic Translation' plugin.
* Update the 'Automatic Translation' plugin to a version beyond 1.0.4 immediately. If an update is unavailable, disable or remove the plugin until a patch is applied.
* Implement web application firewall (WAF) rules to block POST requests directed at /wp-json/automatic-translator/v1/saveDoc.
* Monitor server file systems for the creation of new or unknown files within the plugin directory or web root, particularly PHP files.
