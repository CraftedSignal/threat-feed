---
title: Unauthenticated SQL Injection in Seeyon A6
slug: 2026-09-seeyon-a6-sqli
description: Seeyon A6 contains an unauthenticated SQL injection vulnerability in the downloadAtt.jsp endpoint, allowing remote attackers to extract sensitive database contents via the attach_ids parameter.
date: "2026-09-29T16:28:27Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:seeyon:a6:*:*:*:*:*:*:*:*
tags:
  - sqli
  - vulnerability
  - webserver
vendors:
  - Seeyon
products:
  - A6
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Seeyon A6 collaborative office automation platform contains an unauthenticated SQL injection vulnerability in the attach_ids parameter of the file attachment download endpoint that allows remote attackers to extract arbitrary database contents without prior authentication.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Attackers can inject UNION-based SQL statements through the attach_ids request parameter in downloadAtt.jsp to retrieve sensitive information including credentials and system configuration data.
    confidence_band: high
cves:
  - id: CVE-2015-20122
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2015-20122
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Scan web server access logs for requests to downloadAtt.jsp with UNION-based SQL injection strings in attach_ids.
      owner: SOC
      due: 24h
      evidence: CVE-2015-20122 exploitation description.
  mitigation_plan:
    - priority: immediate
      action: Upgrade or patch Seeyon A6 to a version that addresses CVE-2015-20122.
      owner: IT Operations
      addresses: CVE-2015-20122
      evidence: NVD vulnerability disclosure.
---

Seeyon A6 collaborative office automation platform is vulnerable to an unauthenticated SQL injection vulnerability (CVE-2015-20122). This vulnerability resides in the attach_ids parameter of the downloadAtt.jsp file attachment download endpoint. Remote attackers can leverage this flaw to perform UNION-based SQL injection attacks without requiring prior authentication. By crafting malicious input for the attach_ids parameter, attackers can extract sensitive database information, including credentials and system configuration data. The Shadowserver Foundation first observed evidence of exploitation in the wild on October 17, 2023. Given the sensitivity of the data typically stored in collaborative office automation platforms, this vulnerability presents a significant risk to organizational confidentiality and integrity.

## Impact

Successful exploitation allows for the unauthorized retrieval of sensitive information from the underlying database, including system credentials and configuration settings. This can lead to full compromise of the application, lateral movement within the network, and the potential exfiltration of proprietary or sensitive business documentation stored within the collaborative environment.

## Recommendation

1. Audit web server logs for suspicious POST or GET requests to /downloadAtt.jsp containing SQL keywords (e.g., UNION, SELECT, OR, SLEEP) in the attach_ids parameter.
2. Apply the latest security patches provided by Seeyon for the A6 platform to remediate CVE-2015-20122.
3. Restrict access to the file attachment download functionality at the network or web application firewall level if patching is not immediately feasible.
