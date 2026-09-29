---
title: Improper Authentication Vulnerability in Rebuild Login Endpoint
slug: 2026-09-rebuild-auth-bypass
description: Rebuild versions up to 4.4.7 and 4.5.0-beta5 are vulnerable to an improper authentication flaw in the login component that permits remote attackers to bypass authentication via manipulated requests.
date: "2026-09-29T04:25:01Z"
lastmod: "2026-09-29T04:25:11Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:rebuild:rebuild:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - web-vulnerability
  - cve-2026-102248
  - web-application
  - authorization-bypass
  - cve-2026-102249
vendors:
  - Rebuild
products:
  - Rebuild (<= 4.4.7, 4.5.0-beta5)
  - REBUILD (<= 4.4.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: The manipulation leads to improper authentication at the login endpoint.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument url/fileKey results in missing authorization. It is possible to launch the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-102248
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102248
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102249
rules:
  - title: Detect CVE-2026-102249 - Unauthorized File Save Access
    description: Detects potential exploitation attempts of CVE-2026-102249 by monitoring for POST requests to the file-editor-save endpoint.
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
    - IT Operations
  immediate_actions:
    - action: Review web access logs for suspicious activity targeting /user/login.
      owner: SOC
      due: 24h
      evidence: Source identifies /user/login as the vulnerable component.
  hunt_leads:
    - lead: Anomalous successful logins from IPs that have not established a prior session or from suspicious User-Agent strings.
      technique_id: T1550
      data_needed:
        - Web server access logs (method, URI, status code, source IP)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Public exploit code is available for this endpoint.
updates:
  - at: "2026-09-29T04:25:11Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-102249 - Unauthorized File Save Access'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-102249
---

A security vulnerability (CVE-2026-102248) has been identified in the Rebuild application affecting versions up to 4.4.7 and 4.5.0-beta5. The flaw resides within the Login Endpoint located at /user/login. Attackers can remotely manipulate input sent to this endpoint to trigger an authentication bypass, potentially gaining unauthorized access to the application. Public exploit code for this vulnerability is currently available, increasing the risk of active exploitation. The vendor has not responded to disclosure efforts regarding this issue. Organizations using Rebuild are advised to assess their exposure to this endpoint, as it provides a direct vector for unauthenticated access.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to bypass the application's login mechanism. This can lead to unauthorized access to user accounts, data exposure, and potential administrative control over the application, depending on the privileges of the targeted account.

## Recommendation

1. Implement strict access control lists or Web Application Firewall (WAF) rules to restrict access to /user/login if patching is not possible.
2. Audit web server logs for high-frequency or anomalous POST requests to the /user/login path.
3. Given the lack of a vendor response, monitor the Rebuild application for signs of unauthorized account access or unexpected administrative activity.
