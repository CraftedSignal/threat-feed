---
title: SQL Injection Vulnerability in MingSoft MCMS
slug: 2026-08-mingsoft-mcms-sqli
description: MingSoft MCMS versions up to 3.0.6 contain a remote SQL injection vulnerability in the ms-mdiy component, allowing unauthenticated attackers to manipulate the formFields argument to execute arbitrary database queries.
date: "2026-08-09T15:46:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - sqli
  - vulnerability-management
vendors:
  - MingSoft
products:
  - MCMS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Executing a manipulation of the argument formFields can lead to sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-19355
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19355
rules:
  - title: Detects CVE-2026-19355 Exploitation - SQL Injection in MCMS
    description: Detects potential SQL injection attempts targeting the ModelDataImpl component via the formFields parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review web logs for access to /mdiy/form/data/list.do with anomalous formFields parameters
      owner: SOC
      due: 24h
      evidence: CVE-2026-19355 identifies this specific endpoint and parameter as vulnerable
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to sanitize or block requests to the vulnerable endpoint
      owner: IT Operations
      addresses: CVE-2026-19355
      evidence: Vulnerability allows unauthenticated remote exploitation
---

MingSoft MCMS (versions up to 3.0.6) is susceptible to a critical SQL injection vulnerability identified as CVE-2026-19355. The vulnerability resides within the ModelDataImpl.queryDiyFormData function of the ms-mdiy component. An unauthenticated remote attacker can exploit this by sending a crafted HTTP request to the /mdiy/form/data/list.do endpoint, specifically injecting malicious SQL syntax into the 'formFields' argument. Successful exploitation enables unauthorized data extraction or modification within the underlying database. The vendor has been unresponsive to disclosure efforts, and proof-of-concept exploitation material is publicly available. Defenders should prioritize auditing traffic to the identified endpoint for anomalous SQL keywords or malformed input parameters.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to bypass authentication controls and execute arbitrary SQL commands. Depending on the database permissions of the MCMS application, this could lead to full database compromise, exfiltration of sensitive site data, or potential modification of administrative records, resulting in total loss of application integrity.

## Recommendation

* Monitor web application logs for HTTP requests directed at /mdiy/form/data/list.do that contain SQL control characters (e.g., single quotes, comments, UNION, SELECT) within the formFields parameter.
* Deploy web application firewall (WAF) signatures designed to detect and block SQL injection attempts targeting the listed endpoint.
* Restrict access to the MCMS administrative and data-processing endpoints to trusted IP ranges until a patch is applied by the vendor or internal remediation is implemented.
* Evaluate the application's database user permissions to ensure they follow the principle of least privilege, minimizing the blast radius in the event of successful injection.
