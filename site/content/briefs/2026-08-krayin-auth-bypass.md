---
title: Krayin CRM Installer Authentication Bypass Vulnerability
slug: 2026-08-krayin-auth-bypass
description: Krayin CRM 2.2.4 contains a missing authentication vulnerability in the installer middleware, allowing unauthenticated remote attackers to overwrite the administrator account via crafted HTTP POST requests.
date: "2026-08-03T18:05:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - crm
  - authentication-bypass
vendors:
  - Krayin
products:
  - Krayin CRM (2.2.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Krayin CRM 2.2.4 contains a missing authentication vulnerability in the installer middleware that allows unauthenticated remote attackers to overwrite the primary administrator account.
    confidence_band: high
cves:
  - id: CVE-2026-41452
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41452
rules:
  - title: Detects CVE-2026-41452 Exploitation - Unauthenticated Admin Overwrite via Installer Middleware
    description: Detects exploitation attempts against CVE-2026-41452 where an unauthenticated actor attempts to interact with the admin-config-setup endpoint using the X-Requested-With bypass header.
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to web application firewalls or WAF-enabled load balancers.
      owner: Detection Engineering
      due: 24h
      evidence: Exploitation utilizes a specific HTTP header and endpoint URI path observable in web logs.
  mitigation_plan:
    - priority: immediate
      action: Block access to the /admin-config-setup URI path for all external IP addresses.
      owner: IT Operations
      addresses: CVE-2026-41452
      evidence: Vulnerability exists in the installer middleware.
---

Krayin CRM version 2.2.4 is affected by a critical missing authentication vulnerability (CVE-2026-41452) located within the installer middleware. An unauthenticated remote attacker can bypass the CanInstall middleware redirect by including a specific HTTP header, 'X-Requested-With: XMLHttpRequest', in a POST request directed at the application's configuration endpoint. This flaw permits the attacker to interact with the 'admin-config-setup' endpoint, which contains an 'updateOrInsert' function targeting the hardcoded primary administrator user ID. By submitting arbitrary name, email, and password values, an attacker can overwrite existing administrator credentials, resulting in full administrative compromise of the CRM instance. This vulnerability is of high concern due to the ease of exploitation and the potential for full data access and administrative control over the target CRM environment.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain full administrative access to Krayin CRM instances. This grants the attacker unrestricted access to all stored CRM data, including customer records, sales information, and communications, as well as the ability to modify system settings or further persist within the environment.

## Recommendation

- Immediately restrict access to the CRM installer endpoints using network-level controls until the vendor releases a security update for Krayin CRM 2.2.4.
- Audit access logs for unauthorized HTTP POST requests directed to the 'admin-config-setup' URI path, specifically looking for requests containing the 'X-Requested-With: XMLHttpRequest' header originating from unauthorized IP addresses.
- Review administrative user accounts for anomalous changes or unknown credentials that may indicate post-exploitation account takeover.
