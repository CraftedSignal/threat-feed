---
title: SQL Injection in Helical Insight via /executeDatasource
slug: 2026-10-helical-insight-sql-injection
description: Helical Insight versions through 7.0.0 contain an authenticated SQL injection vulnerability in the /executeDatasource endpoint that allows attackers to manipulate backend database queries.
date: "2026-10-16T18:47:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:helicalinsight:helical_insight:*:*:*:*:*:*:*:*
vendors:
  - Helical Insight
products:
  - Helical Insight (<= 7.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Helical Insight through 7.0.0 contains an sql injection vulnerability that allows authenticated viewers to inject SQL through unescaped report parameter values sent to /executeDatasource.
    confidence_band: high
cves:
  - id: CVE-2026-111634
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111634
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review /executeDatasource access logs for SQL injection patterns
      owner: SOC
      due: 24h
      evidence: CVE-2026-111634 description
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version beyond 7.0.0 once patch is released
      owner: IT Operations
      addresses: CVE-2026-111634
      evidence: Source reporting version vulnerability
---

Helical Insight through version 7.0.0 contains a critical SQL injection vulnerability (CVE-2026-111634) within its report parameter processing mechanism. The flaw resides in the /executeDatasource endpoint, where the application fails to properly sanitize Numeric and String placeholder values. Because the internal SqlDetect filter fails to correctly validate these inputs, an authenticated user can inject arbitrary SQL commands. This vulnerability allows an attacker to bypass existing security controls to perform unauthorized operations, including reading sensitive data from tables that should be restricted or modifying existing records within the report's backend data source. With a CVSS score of 8.1, this flaw presents a significant risk for environments where report viewers have access to sensitive analytical databases.

## Impact

Successful exploitation allows authenticated attackers to gain unauthorized access to backend database content, potentially leading to data exfiltration or integrity loss. The scope of impact is limited to the data sources accessible by the Helical Insight application, but in enterprise environments, this often includes broad access to business intelligence repositories.

## Recommendation

- Upgrade Helical Insight to a version beyond 7.0.0 immediately upon release of a security patch.
- Review access logs for the /executeDatasource endpoint to identify unusual parameter payloads containing common SQL injection syntax (e.g., symbols such as single quotes, double dashes, or UNION/SELECT keywords).
- Implement strict input validation at the Web Application Firewall (WAF) layer for all requests directed to /executeDatasource to block malicious SQL patterns.
- Audit database permissions for the service account utilized by Helical Insight to ensure it adheres to the principle of least privilege, preventing full database compromise in the event of an injection.
