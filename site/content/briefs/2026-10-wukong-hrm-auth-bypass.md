---
title: Authentication Bypass in Wukong_HRM ParamAspect
slug: 2026-10-wukong-hrm-auth-bypass
description: Wukong_HRM up to commit 186115e contains an authentication bypass vulnerability in ParamAspect that allows unauthenticated attackers to access sensitive HR administrative API endpoints.
date: "2026-10-11T03:58:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:wukong_hrm:wukong_hrm:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - web-application
  - data-exfiltration
vendors:
  - Wukong_HRM
products:
  - Wukong_HRM (<= commit 186115e)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: The authentication bypass allows unauthenticated attackers to call every HRM API endpoint by omitting the AUTH-TOKEN header.
    confidence_band: high
cves:
  - id: CVE-2026-108707
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108707
rules:
  - title: Detect CVE-2026-108707 Exploitation - Missing AUTH-TOKEN Header
    description: Detects potential CVE-2026-108707 exploitation by identifying HTTP requests to Wukong_HRM API endpoints that lack the required AUTH-TOKEN header.
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Wukong_HRM to a version post-commit 186115e
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure for CVE-2026-108707
  hunt_leads:
    - lead: Search logs for 200 OK responses to /api/ endpoints that lack the AUTH-TOKEN header
      technique_id: T1190
      data_needed:
        - Web server access logs with full header visibility
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows unauthenticated access by omitting AUTH-TOKEN
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rule to block requests to /api/ where AUTH-TOKEN header is missing
      owner: IT Operations
      addresses: CVE-2026-108707
      evidence: Source document confirms missing header causes authentication bypass
---

Wukong_HRM, a human resource management platform, contains a critical authentication bypass vulnerability in the ParamAspect component affecting all versions through commit 186115e. The vulnerability resides in the application's request processing logic, which improperly validates authentication tokens. Specifically, the system fails to enforce security checks if the required 'AUTH-TOKEN' header is simply omitted from the HTTP request. This flaw allows unauthenticated remote attackers to interact with restricted API endpoints that are intended for HR administrators only. Successful exploitation grants attackers unauthorized access to sensitive company-wide HR information, including employee personal data, salary histories, and payslips. Furthermore, attackers can leverage this access to modify or delete critical HR records, leading to potential data integrity loss and severe privacy breaches.

## Impact

The vulnerability carries a CVSS v3.1 base score of 9.8, indicating its severity. If exploited, an attacker gains full HR administrator privileges. Potential damage includes the mass exfiltration of sensitive employee PII and payroll information, unauthorized termination of employees, modification of compensation records, and deletion of internal HR documentation. Any organization using Wukong_HRM versions up to commit 186115e is currently at risk of full administrative compromise.

## Recommendation

1. Immediately audit all web server logs for HTTP requests to the Wukong_HRM API that do not contain the 'AUTH-TOKEN' header, as these may indicate exploitation attempts.
2. Patch Wukong_HRM by updating to a version beyond commit 186115e.
3. Deploy web application firewall (WAF) rules to inspect incoming traffic and block API requests missing the mandatory 'AUTH-TOKEN' header.
