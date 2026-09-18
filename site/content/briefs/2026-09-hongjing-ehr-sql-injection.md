---
title: SQL Injection in Hongjing e-HR /servlet/codesettree
slug: 2026-09-hongjing-ehr-sql-injection
description: Hongjing e-HR versions prior to 8.2 are vulnerable to unauthenticated SQL injection via the categories parameter in the /servlet/codesettree endpoint, allowing remote attackers to extract sensitive database content.
date: "2026-09-18T20:06:56Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:hongjing:e-hr:*:*:*:*:*:*:*:*
tags:
  - web-application
  - injection
  - vurnerability
vendors:
  - Hongjing
products:
  - e-HR (< 8.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can supply a crafted UNION SELECT payload to read arbitrary database content.
    confidence_band: high
cves:
  - id: CVE-2023-54399
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-54399
rules:
  - title: Detects CVE-2023-54399 Exploitation - Unauthenticated SQL Injection in e-HR
    description: Detects attempts to exploit CVE-2023-54399 via malicious UNION SELECT payloads in the categories parameter of the /servlet/codesettree endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Hongjing e-HR to version 8.2 or later
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  hunt_leads:
    - lead: Search logs for unusual database query patterns or UNION SELECT strings in /servlet/codesettree
      technique_id: T1190
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Shadowserver observed exploitation
  mitigation_plan:
    - priority: immediate
      action: Patch Hongjing e-HR to 8.2
      owner: IT Operations
      addresses: CVE-2023-54399
      evidence: NVD remediation guidance
---

Hongjing e-HR versions prior to 8.2 contain a critical SQL injection vulnerability residing in the /servlet/codesettree endpoint. The application fails to properly sanitize the 'categories' query parameter after stripping HRMS-specific encoding, allowing an unauthenticated remote attacker to inject malicious SQL syntax. This vulnerability permits the execution of UNION SELECT statements, which can be leveraged to query arbitrary tables within the backend database. Defenders should note that this flaw can be exploited to exfiltrate sensitive data, including administrative credentials from the operuser table. This vulnerability has been subject to active exploitation in the wild since October 2023, as identified by the Shadowserver Foundation.

## Impact

Successful exploitation allows unauthenticated attackers to gain unauthorized access to sensitive corporate data. By targeting credential tables such as operuser, attackers can obtain account information, facilitating further unauthorized access to the HR management system and potentially lateral movement within the network. This affects organizations utilizing Hongjing e-HR globally.

## Recommendation

1. Upgrade all instances of Hongjing e-HR to version 8.2 or higher immediately to address the underlying vulnerability.
2. Implement strict input validation on the /servlet/codesettree endpoint to reject requests containing SQL keywords or metacharacters in the categories parameter.
3. Monitor web access logs for suspicious HTTP requests targeting /servlet/codesettree containing UNION, SELECT, or character manipulation strings.
4. Perform a security audit of the backend database to check for unauthorized access or dumped credential records following the timeline of observed exploitation (since October 2023).
