---
title: Privilege Escalation via IDOR in CamaleonCMS
slug: 2026-08-camaleoncms-idor
description: CamaleonCMS versions 2.9.2 and earlier are vulnerable to privilege escalation via an IDOR parameter confusion flaw in the UsersController, allowing authenticated attackers to overwrite arbitrary user credentials.
date: "2026-08-11T18:36:28Z"
lastmod: "2026-08-12T20:58:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - xss
  - injection
vendors:
  - CamaleonCMS
products:
  - CamaleonCMS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: CamaleonCMS version 2.9.2 and earlier contains a privilege escalation vulnerability via insecure direct object reference.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can manipulate plugin configuration parameters at runtime... enabling account takeover when chained with stored cross-site scripting.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Attackers can submit a malicious HTML payload as a draft title through the drafts creation endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-56721
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56721
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73326
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73329
rules:
  - title: Detects CVE-2026-56721 Exploitation - Mismatched Parameters in UsersController
    description: Detects exploitation of CVE-2026-56721 where a PATCH request contains distinct 'id' and 'user_id' parameters targeting the update_ajax endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Patch CamaleonCMS to version 2.9.3 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-56721 NVD advisory
    - action: Deploy Sigma rule to detect mismatched parameter exploitation
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-56721 parameter confusion flaw
  mitigation_plan:
    - priority: immediate
      action: Monitor PATCH /update_ajax requests for ID mismatches
      owner: SOC
      addresses: CVE-2026-56721
      evidence: NVD vulnerability details
updates:
  - at: "2026-08-12T20:58:37Z"
    level: L2
    summary: added coverage for CamaleonCMS
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-73326
  - at: "2026-08-12T20:58:43Z"
    level: L2
    summary: added coverage for CamaleonCMS
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-73329
---

CamaleonCMS versions 2.9.2 and earlier contain a critical privilege escalation vulnerability (CVE-2026-56721) stemming from an Insecure Direct Object Reference (IDOR) flaw within the UsersController. The vulnerability resides in a parameter confusion discrepancy between the authorization filter, which checks the 'id' parameter, and the action body, which processes the 'user_id' parameter. An authenticated low-privileged attacker can exploit this by crafting a PATCH request to the 'update_ajax' endpoint. By setting the 'id' parameter to their own identifier to satisfy the authorization filter, and concurrently setting the 'user_id' parameter to an administrator or target user's identifier, the application logic incorrectly loads and mutates the victim's account. Successful exploitation allows for the modification of any user's credentials, facilitating a full site takeover. Defenders should prioritize patching or implementing request validation logic to ensure parameter consistency.

## Attack Chain

1. Attacker gains authenticated access to the target application with a low-privileged account.
2. Attacker discovers the 'update_ajax' PATCH endpoint used for user profile management.
3. Attacker crafts a malicious HTTP PATCH request targeting the '/update_ajax' route.
4. Attacker includes their own user ID in the 'id' parameter to bypass the authorization filter.
5. Attacker includes the victim's (e.g., admin) user ID in the 'user_id' parameter within the request body.
6. The application performs the authorization check against the attacker's ID, which succeeds.
7. The application processes the request body, using the victim's ID to perform the update.
8. The victim's password or other sensitive account information is overwritten by the attacker, achieving account takeover.

## Impact

Successful exploitation of CVE-2026-56721 allows an unprivileged attacker to escalate privileges to administrator status. This grants the attacker full control over the CamaleonCMS instance, potentially leading to unauthorized data exfiltration, system configuration changes, or the deployment of additional malicious persistence mechanisms. The impact is significant for organizations relying on CamaleonCMS for content management, as it provides a direct path to site-wide administrative compromise.

## Recommendation

* Update CamaleonCMS to the latest patched version immediately to remediate CVE-2026-56721.
* Deploy the provided Sigma rule to web server logs to monitor for unauthorized 'update_ajax' PATCH requests with mismatched 'id' and 'user_id' parameter combinations.
* Review web application access logs for repeated PATCH requests to 'update_ajax' originating from non-administrative accounts.
