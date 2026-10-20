---
title: Privilege Escalation in Webkul Krayin CRM via SVG XSS
slug: 2026-10-krayin-crm-xss
description: CVE-2025-3568 allows an authenticated low-privileged user to perform an administrative account takeover in Krayin CRM 2.0.0 and 2.1.0 by leveraging SVG-based XSS to bypass password verification controls.
date: "2026-10-20T07:35:10Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:webkul:krayin_crm:2.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:webkul:krayin_crm:2.1.0:*:*:*:*:*:*:*
tags:
  - web-application
  - privilege-escalation
  - xss
  - csrf
vendors:
  - Webkul
products:
  - Krayin CRM (2.0.0, 2.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: Attacker (low-privilege user) sends an email with a malicious SVG attachment to an admin.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: JavaScript inside the SVG executes, harvesting the admin's XSRF-TOKEN cookie.
    confidence_band: high
cves:
  - id: CVE-2025-3568
    cvss: 3.5
    epss: 0.0043
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-3568
  - https://vuldb.com/?id.304609
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SHELLKRAFT-CVE-2025-3568
rules:
  - title: Detects CVE-2025-3568 Exploitation - Unauthorized Admin Password Change Attempt
    description: Detects potential exploitation of CVE-2025-3568 by monitoring POST requests to the user management edit endpoint, which may indicate a CSRF attempt when not accompanied by expected user activity
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
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Krayin CRM to the latest secure version
      owner: IT Operations
      due: 24h
      evidence: Vulnerability documented in CVE-2025-3568
  hunt_leads:
    - lead: Search web access logs for successful requests to /admin/settings/users/edit/ originating from low-privilege user accounts
      technique_id: T1566.001
      data_needed:
        - HTTP access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit documentation highlights account takeover via this endpoint
  mitigation_plan:
    - priority: immediate
      action: Disable SVG file uploads in Krayin CRM configuration
      owner: IT Operations
      addresses: CVE-2025-3568
      evidence: Vulnerability is rooted in malicious SVG processing
---

Webkul Krayin CRM versions 2.0.0 and 2.1.0 contain a vulnerability (CVE-2025-3568) that enables privilege escalation via malicious SVG file uploads. The application fails to properly sanitize uploaded SVG files, allowing attackers to embed malicious JavaScript. When an administrator views or interacts with the uploaded file, the script executes in the context of the admin's session. Combined with a lack of current password verification on the user profile update API endpoint, an attacker can perform a Cross-Site Request Forgery (CSRF) attack to overwrite the administrative account password. This vulnerability enables full account takeover and unauthorized access to sensitive customer relationship management data.

## Attack Chain

1. Attacker (with low-privilege access) crafts a malicious SVG file containing an XSS payload designed to exfiltrate session tokens and initiate a password change request.
2. Attacker uploads the malicious SVG file through a permitted CRM upload vector (e.g., email attachment or user profile media).
3. Attacker triggers the administrator to open or preview the SVG file, which renders in the admin's browser session.
4. The embedded JavaScript in the SVG executes, capturing the administrator's CSRF/XSRF tokens from the browser session.
5. The script generates an unauthorized background request to the user management API (`/admin/settings/users/edit/[ID]`).
6. The application processes the request, which fails to verify the current administrative password.
7. The administrator account password is changed to a value specified by the attacker.
8. Attacker logs into the CRM using the newly set credentials to gain full administrative control.

## Impact

Successful exploitation results in full administrative account takeover. Impacted sectors include businesses using Krayin CRM to manage customer, financial, and lead information. The attack allows for unauthorized data exfiltration, backdooring of the CRM instance, and potential lateral movement or persistence within the business environment.

## Recommendation

1. Patch Webkul Krayin CRM to a non-vulnerable version immediately.
2. Disable the ability to upload or render SVG files within the CRM interface until a vendor patch is applied.
3. Implement strict Content Security Policy (CSP) headers to prevent the execution of inline scripts and unauthorized API requests from origin domains.
4. Enable server-side validation for all administrative user management actions, requiring current password re-authentication for all account profile changes.
5. Deploy the provided Sigma rule to detect POST requests to administrative user management endpoints that lack necessary authentication context or originate from non-standard user agents.
