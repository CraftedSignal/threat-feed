---
title: Authentication Bypass in AdithyaYelloju Restaurant-Management-System
slug: 2026-10-restaurant-mgmt-auth-bypass
description: An authentication bypass vulnerability in the AdithyaYelloju Restaurant-Management-System allows remote attackers to gain unauthorized access via manipulated login credentials.
date: "2026-10-13T10:34:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:adithyayelloju:restaurant-management-system:*:*:*:*:*:*:*:*
vendors:
  - AdithyaYelloju
products:
  - Restaurant-Management-System (<= 7f0e7e84255e8fcfd488e83f8f91451bbbff6b9c)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Such manipulation of the argument email/passwd leads to improper authentication.
    confidence_band: high
cves:
  - id: CVE-2026-109114
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109114
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all servers running the AdithyaYelloju Restaurant-Management-System
      owner: IT Operations
      due: 24h
      evidence: System affected by CVE-2026-109114
    - action: Deploy WAF rules to monitor or block requests to /User/login.php from untrusted sources
      owner: SOC
      due: 24h
      evidence: Vulnerability in User/login.php component
  hunt_leads:
    - lead: Analyze web server logs for high frequency or anomalous POST requests to /User/login.php
      technique_id: T1078
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows remote manipulation of login arguments
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the web server login interface
      owner: IT Operations
      addresses: CVE-2026-109114
      evidence: Remote exploitation of User/login.php
---

The AdithyaYelloju Restaurant-Management-System, a project using a rolling release model, contains an authentication bypass vulnerability (CVE-2026-109114) within the 'User/login.php' component. The flaw allows remote, unauthenticated attackers to manipulate the 'email' or 'passwd' arguments to successfully authenticate to the application. This vulnerability is publicly disclosed, and as of the current reporting, the maintainer has not provided a patch or a response to the disclosed issue. Due to the rolling release nature of the software, specific version numbers are unavailable, and all instances up to commit 7f0e7e84255e8fcfd488e83f8f91451bbbff6b9c should be considered vulnerable. Defenders must monitor for unauthorized access attempts targeting this specific login endpoint.

## Attack Chain

1. Attacker performs reconnaissance to identify the target web server running the Restaurant-Management-System.
2. Attacker navigates to the login page hosted at '/User/login.php'.
3. Attacker intercepts the POST request sent to the login endpoint.
4. Attacker modifies the 'email' or 'passwd' parameters with malicious input designed to bypass authentication logic.
5. The vulnerable 'User/login.php' script improperly validates the input, granting the attacker an authenticated session.
6. Attacker leverages the hijacked administrative or user session to interact with the application.
7. Attacker proceeds to exfiltrate restaurant data or modify system configurations.

## Impact

Successful exploitation allows remote attackers to bypass authentication entirely, gaining unauthorized access to the application. This could lead to the exposure of sensitive restaurant data, modification of management settings, or further system compromise. The severity is marked as high (CVSS 7.3), and the public availability of an exploit increases the likelihood of opportunistic targeting.

## Recommendation

Prioritize the identification of all internet-facing instances of the AdithyaYelloju Restaurant-Management-System in your environment. Since no official patch is currently available, implement web application firewall (WAF) rules to restrict access to the '/User/login.php' endpoint for unknown or suspicious source IPs. Conduct a review of application access logs for anomalous login patterns or successful logins associated with common bypass payloads. If the system is not critical, consider disabling the affected service until a security update is released by the maintainer.
