---
title: SQL Injection Vulnerability in Dolusoft SOPLOG
slug: 2026-09-sql-injection-soplog
description: An improper neutralization vulnerability (CVE-2026-82307) in Dolusoft SOPLOG prior to version 2026.9.4.1 allows unauthenticated attackers to execute arbitrary SQL commands against the backend database.
date: "2026-09-30T14:35:04Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:dolusoft_software_technologies:soplog:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sqli
  - sql-injection
vendors:
  - Dolusoft Software Technologies
products:
  - SOPLOG (< 2026.9.4.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Improper neutralization of special elements used in an SQL command ('SQL injection') vulnerability in Dolusoft Software Technologies SOPLOG allows SQL Injection.
    confidence_band: high
cves:
  - id: CVE-2026-82307
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82307
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade SOPLOG to 2026.9.4.1 or later to remediate CVE-2026-82307
      owner: IT Operations
      due: 48h
      evidence: Source states issue affects SOPLOG before version 2026.9.4.1
  mitigation_plan:
    - priority: immediate
      action: Upgrade SOPLOG to 2026.9.4.1
      owner: IT Operations
      addresses: CVE-2026-82307
      evidence: NVD vulnerability details
---

Dolusoft Software Technologies SOPLOG contains a critical SQL injection vulnerability identified as CVE-2026-82307. The flaw arises from the improper neutralization of special characters and SQL elements within application inputs. An unauthenticated, remote attacker can leverage this vulnerability to inject malicious SQL commands, which are then executed with the privileges of the database service account. This allows for unauthorized access to sensitive data, modification of existing database records, or potential deletion of tables. The vulnerability is present in all versions of SOPLOG prior to 2026.9.4.1. Security teams should prioritize patching this software to prevent potential data exfiltration or integrity loss resulting from unauthorized database interactions.

## Impact

Successful exploitation allows an unauthenticated attacker to execute arbitrary SQL commands, potentially leading to full compromise of the database backend. This can result in unauthorized exfiltration of sensitive organizational data, manipulation of business records, or total service disruption, impacting the confidentiality and integrity of all data managed by the SOPLOG application.

## Recommendation

- Upgrade SOPLOG to version 2026.9.4.1 or later to remediate the vulnerability associated with CVE-2026-82307.
- Review web server access logs for anomalous SQL syntax or characters, such as UNION, SELECT, or comment indicators (--), in common query parameters or POST bodies.
- Ensure the database account used by the SOPLOG web application follows the principle of least privilege, restricting its permissions only to necessary tables and operations.
