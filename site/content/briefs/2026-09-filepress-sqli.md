---
title: SQL Injection in FilePress Publish Module
slug: 2026-09-filepress-sqli
description: An unpatched SQL injection vulnerability in zyx0814 FilePress versions 3.0.1 and earlier allows remote attackers to manipulate the orderby or order arguments within search.php.
date: "2026-09-15T05:38:48Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:zyx0814:filepress:*:*:*:*:*:*:*:*
tags:
  - sqli
  - web-vulnerability
vendors:
  - zyx0814
products:
  - FilePress (<= 3.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-90879
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90879
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Implement WAF blocking for SQL injection patterns targeting dzz/publish/search.php
      owner: SOC
      due: 24h
      evidence: CVE-2026-90879 identifies dzz/publish/search.php as the injection vector.
  mitigation_plan:
    - priority: immediate
      action: Monitor for official patches and update FilePress to versions beyond 3.0.1
      owner: IT Operations
      addresses: CVE-2026-90879
      evidence: Source states no patch currently exists; monitoring for remediation is required.
---

CVE-2026-90879 describes a high-severity SQL injection vulnerability discovered in the zyx0814 FilePress software, affecting all versions up to and including 3.0.1. The flaw exists within the Publish Module, specifically in the dzz/publish/search.php file. By sending a crafted HTTP request, an unauthenticated remote attacker can inject arbitrary SQL commands via the 'orderby' or 'order' parameters. This vulnerability stems from improper neutralization of special elements used in an SQL command. As of the time of reporting, the project maintainers have not issued a patch to remediate this flaw, and public exploit code is available, increasing the risk of active exploitation. Defenders should monitor web traffic targeting the Publish Module for signs of SQL injection patterns.

## Impact

Successful exploitation of this vulnerability allows remote attackers to perform unauthorized database operations, potentially leading to data exfiltration, modification, or, depending on database permissions, remote code execution. Given the public availability of exploit code, all FilePress instances running version 3.0.1 or earlier are at high risk of compromise.

## Recommendation

- Implement temporary Web Application Firewall (WAF) rules to inspect and block requests to dzz/publish/search.php containing SQL syntax characters in the 'orderby' or 'order' parameters.
- Monitor web server logs for suspicious spikes in POST or GET requests to the identified vulnerable path that deviate from established baselines.
- Apply the vendor patch as soon as it becomes available; monitor the zyx0814 repository for version 3.0.2 or subsequent security updates.
