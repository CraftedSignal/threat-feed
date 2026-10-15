---
title: SQL Injection Vulnerability in Easycms
slug: 2026-10-easycms-sqli
description: CVE-2026-3786 is a high-severity SQL injection vulnerability in Easycms version 1.6 and earlier that allows remote attackers to execute arbitrary database commands via the _order parameter.
date: "2026-10-15T20:04:40Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:easycms:easycms:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sqli
  - remote-execution
vendors:
  - Easycms
products:
  - Easycms (<= 1.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SQL injection via manipulation of _order parameter in RbacuserAction.class.php (Request Parameter Handler).
    confidence_band: high
cves:
  - id: CVE-2026-3786
    cvss: 6.3
    epss: 0.005
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3786
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-MEFHIKA120-CVE-2026-3786
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Easycms to a version greater than 1.6.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-3786 impacts versions 1.6 and earlier.
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to sanitize or block input on the _order query parameter in requests to RbacuserAction.class.php.
      owner: Security Engineering
      addresses: CVE-2026-3786
      evidence: SQL injection vulnerability via _order parameter.
---

CVE-2026-3786 is a high-severity SQL injection vulnerability affecting Easycms versions 1.6 and earlier. The flaw resides in the 'RbacuserAction.class.php' component, specifically within the handling of the '_order' query parameter. An attacker with low-level privileges can inject malicious SQL statements into this parameter, leading to unauthorized database access, potential data exfiltration, or modification. With the public release of a Proof-of-Concept (PoC) exploit on October 15, 2026, the risk of exploitation has increased for organizations running outdated instances of the platform.

## Impact

Successful exploitation of CVE-2026-3786 allows an attacker to achieve full control over the database back-end. This can lead to total compromise of application data, including user credentials and sensitive business information. The CVSS score of 8.8 reflects the high impact on confidentiality, integrity, and availability. All deployments of Easycms version 1.6 or earlier are considered vulnerable and at risk of exploitation.

## Recommendation

* Upgrade to the latest version of Easycms immediately to mitigate the risk associated with CVE-2026-3786.
* Audit web server logs for HTTP requests containing suspicious SQL injection patterns (such as keywords: SELECT, UNION, FROM, SLEEP, or comment indicators like --) directed at 'RbacuserAction.class.php'.
* Implement Web Application Firewall (WAF) rules to inspect query parameters for SQL metacharacters and block malicious requests targeting the '_order' parameter.
