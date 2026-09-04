---
title: SQL Injection Vulnerability in Sangoma Switchvox
slug: 2026-09-sangoma-switchvox-sqli
description: Sangoma Switchvox is vulnerable to an unauthenticated SQL injection flaw that allows remote attackers to execute arbitrary SQL commands on the backend PostgreSQL database, potentially leading to remote code execution.
date: "2026-09-02T17:56:24Z"
lastmod: "2026-09-04T14:06:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:sangoma:switchvox:*:*:*:*:*:*:*:*
  - cpe:2.3:a:sangoma:switchvox:*:*:*:*:on-premises:*:*:*
tags:
  - webserver
  - sql-injection
  - vulnerability
  - cisa-kev
vendors:
  - Sangoma
products:
  - Switchvox (< 8.4.0.2)
  - Switchvox (< 8.4.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Sangoma Switchvox contains a SQL injection vulnerability which allows an unauthenticated remote attacker to execute arbitrary SQL statements.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Successful exploitation can lead to database manipulation and remote code execution on the affected appliance.
    confidence_band: high
cves:
  - id: CVE-2026-9586
    cvss: 9.8
    epss: 0.11845
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-9586
  - https://sangomakb.atlassian.net/wiki/spaces/Switchvox/pages/1802371073/Switchvox+-+Release+Notes+Version+8.4.0.2+July+14+2026
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9586
  - https://www.securityweek.com/sangoma-switchvox-vulnerabilities-exploited-in-the-wild/
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade all internet-facing Switchvox instances to version 8.4.0.2.
      owner: IT Operations
      due: "2026-09-05"
      evidence: CISA KEV requirement for CVE-2026-9586.
  mitigation_plan:
    - priority: immediate
      action: Restrict management interface access to internal/trusted IP ranges via firewall rules.
      owner: Network Security
      addresses: CVE-2026-9586
      evidence: General mitigation for public-facing RCE/SQLi vulnerabilities.
updates:
  - at: "2026-09-04T14:06:15Z"
    level: L1
    summary: new product
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/sangoma-switchvox-vulnerabilities-exploited-in-the-wild/
---

Sangoma Switchvox versions prior to 8.4.0.2 are affected by a critical SQL injection vulnerability (CVE-2026-9586). This flaw enables an unauthenticated, remote attacker to interact with the backend PostgreSQL database by sending a single, specifically crafted HTTP request to the appliance. Successful exploitation grants the attacker the ability to execute arbitrary SQL statements. Depending on the database configuration and permissions, this capability may be leveraged to manipulate sensitive data or achieve remote code execution on the underlying appliance, which is typically used for telecommunications and VoIP services. Given the nature of these appliances, they are often internet-facing, increasing the risk of widespread automated scanning and exploitation. Organizations utilizing Switchvox must prioritize upgrading to version 8.4.0.2 or later in accordance with CISA Binding Operational Directive 26-04.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to gain unauthorized access to the backend database of affected Sangoma Switchvox appliances. This can result in the full compromise of the device, data exfiltration, service disruption, or the potential for lateral movement within the network where the appliance is deployed. As a critical vulnerability listed in the CISA Known Exploited Vulnerabilities (KEV) catalog, it poses an immediate risk to any enterprise-grade deployment.

## Recommendation

* Immediately upgrade all Sangoma Switchvox instances to version 8.4.0.2 or later to remediate CVE-2026-9586.
* Evaluate the internet exposure of all Switchvox appliances and apply access control lists (ACLs) to restrict access to management interfaces to trusted IP addresses only.
* Adhere to CISA BOD 26-04 guidelines for prioritizing security updates and perform forensics triage on any appliances that show signs of unauthorized access or anomalous activity.
