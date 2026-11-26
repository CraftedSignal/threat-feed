---
brief_id: brief-2026-11-26-adobe-campaign-classic-vulnerabilities
event_id: brief-2026-11-26-adobe-campaign-classic-vulnerabilities
revision: 1
activity_at: "2026-11-26T14:38:54Z"
title: 'Adobe Campaign Classic: Code injection and authorization vulnerabilities (CVE-2026-123342, CVE-2026-123721)'
slug: 2026-11-adobe-campaign-classic-vulnerabilities
description: Adobe Campaign Classic is vulnerable to remote code execution and privilege escalation, allowing low-privileged attackers to gain unauthorized access and control over sensitive marketing data.
date: "2026-11-26T14:38:54Z"
type: threat
types:
  - threat
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: All facts sourced from NCSC-NL and CVE Program
cpes:
  - cpe:2.3:a:adobe:campaign_classic:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - privilege-escalation
vendors:
  - Adobe
products:
  - Adobe Campaign Classic (7.4.4 build 9403 and earlier, 7.4.5 build 9420 and earlier)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adobe Campaign Classic (ACC) is affected by an Improper Control of Generation of Code ('Code Injection') vulnerability that could result in arbitrary code execution in the context of the current user.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Adobe Campaign Classic (ACC) is affected by an Incorrect Authorization vulnerability that could result in privilege escalation.
    confidence_band: high
cves:
  - id: CVE-2026-123342
    cvss: 9.9
    epss: 0.00886
    kev_status: "false"
  - id: CVE-2026-123721
    cvss: 9.6
    epss: 0.00749
    kev_status: "false"
references:
  - https://www.ncsc.nl/alerts/kwetsbaarheden-in-adobe-campaign-classic-update-zo-snel-mogelijk
  - https://cveawg.mitre.org/api/cve/CVE-2026-123342
  - https://cveawg.mitre.org/api/cve/CVE-2026-123721
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all Adobe Campaign Classic deployments to identify versions 7.4.4 build 9403, 7.4.5 build 9420, and earlier.
      owner: IT Operations
      due: 24h
      evidence: Welke versies zijn kwetsbaar? 7.4.4 build 9403 en 7.4.5 build 9420 en eerdere versies
    - action: Upgrade affected Adobe Campaign Classic instances to 7.4.4 build 9404 or 7.4.5 build 9421 or later.
      owner: IT Operations
      due: 48h
      evidence: Adobe heeft updates uitgebracht die deze kwetsbaarheden aanpakken.
  hunt_leads:
    - lead: Monitor application logs for unusual command execution, unexpected administrative privilege assignments, or unauthorized API access patterns originating from the Campaign Classic application server.
      technique_id: T1059
      data_needed:
        - Application access logs
        - System audit logs
        - Web server request logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Een aanvaller met weinig rechten op afstand kan worden misbruikt om schadelijke code uit te voeren, toegang te krijgen tot gevoelige informatie en hogere rechten te verkrijgen binnen het systeem.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to build 7.4.4 build 9404, 7.4.5 build 9421 or later.
      owner: IT Operations
      addresses: CVE-2026-123342, CVE-2026-123721
      evidence: Welke versies zijn kwetsbaar? 7.4.4 build 9403 en 7.4.5 build 9420 en eerdere versies
---

## Overview
Multiple vulnerabilities have been identified in Adobe Campaign Classic, including code injection (CVE-2026-123342) and incorrect authorization (CVE-2026-123721). These flaws enable a remote, low-privileged attacker to execute arbitrary code, bypass security controls, and escalate privileges. Successful exploitation can lead to full system compromise, sensitive data exfiltration, and unauthorized script execution in user browsers, potentially leading to session hijacking. The NCSC-NL confirms these vulnerabilities are high risk. There is no current evidence of active exploitation in the wild.

## Impact
Successful exploitation allows attackers to execute commands as the application user, bypass security measures, access confidential customer data, and disrupt marketing operations through account and session compromise.

## Recommendation
Upgrade Adobe Campaign Classic instances to build 7.4.4 build 9404 or 7.4.5 build 9421 or later. If you are unable to confirm your version, contact your IT service provider immediately to inventory affected installations and apply the necessary patches.
