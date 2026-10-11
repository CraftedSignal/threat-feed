---
title: SQL Injection Vulnerability in Xinhu Rainrock RockOA
slug: 2026-10-rockoa-sql-injection
description: A SQL injection vulnerability (CVE-2026-108571) in Xinhu Rainrock RockOA versions 2.7.6 and earlier allows remote attackers to execute arbitrary database queries via the ID argument.
date: "2026-10-11T12:00:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:xinhu:rockoa:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sql-injection
  - cve-2026-108571
vendors:
  - Xinhu
products:
  - RockOA (<= 2.7.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack is possible to be carried out remotely.
    confidence_band: high
cves:
  - id: CVE-2026-108571
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108571
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block external access to the openkqjAction.php endpoint on all RockOA instances
      owner: SOC
      due: 24h
      evidence: Vulnerability located in webmain/task/openapi/openkqjAction.php
  hunt_leads:
    - lead: Search web logs for POST or GET requests to openkqjAction.php with suspicious ID parameter values
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Manipulation of the argument ID causes sql injection
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the vulnerable endpoint via WAF or firewall rules
      owner: IT Operations
      addresses: CVE-2026-108571
      evidence: Public exploit availability
---

A SQL injection vulnerability exists in Xinhu Rainrock RockOA versions 2.7.6 and earlier, specifically within the kqjcmdModel::returnchuli function of the openkqjAction.php file. The vulnerability is located in the Openkqj Action component and is triggered by improper sanitization of the ID argument during web requests. Remote attackers can leverage this flaw to manipulate database queries, potentially leading to unauthorized data exfiltration or modification. The vulnerability has been publicly disclosed, and proof-of-concept exploit code is currently circulating. The vendor, Xinhu, was notified prior to public disclosure but failed to respond, and no official patch is currently available. Organizations utilizing RockOA in internet-facing environments are at high risk of exploitation by automated scanners and opportunistic attackers.

## Impact

Successful exploitation allows unauthenticated remote attackers to perform unauthorized database operations. This can lead to full compromise of the application data stored within the backend database, potentially including administrative credentials, user information, or sensitive organizational records. Given the public availability of exploit code, the risk of automated mass exploitation is high.

## Recommendation

Prioritize the identification of all internet-facing Xinhu Rainrock RockOA instances within the environment. Since no patch is available, implement restrictive access controls at the web application firewall (WAF) or network perimeter to block requests targeting the openkqjAction.php endpoint. Monitor web server logs for suspicious patterns in the ID parameter, particularly the inclusion of SQL syntax characters such as single quotes, semicolons, or common SQL injection keywords like UNION, SELECT, or SLEEP.
