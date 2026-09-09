---
title: Hardcoded Session Encryption Key in MaxSite CMS
slug: 2026-09-maxsite-hardcoded-key
description: MaxSite CMS versions 109.6 and earlier contain a hardcoded encryption key in application/config/config.php, enabling unauthenticated attackers to forge administrator session cookies.
date: "2026-09-09T19:01:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:maxsite:maxsite_cms:*:*:*:*:*:*:*:*
tags:
  - web
  - cve
  - authentication-bypass
vendors:
  - MaxSite CMS
products:
  - MaxSite CMS (<= 109.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: This vulnerability allows an unauthenticated remote attacker to calculate valid session cookies using the known key, enabling them to impersonate administrators.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.004
    technique_name: 'Unsecured Credentials: Private Keys'
    evidence: MaxSite CMS versions 109.6 and earlier contain a hardcoded session encryption key within application/config/config.php.
    confidence_band: high
cves:
  - id: CVE-2026-87929
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87929
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all MaxSite CMS instances to a version later than 109.6 to patch CVE-2026-87929.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-87929 advisory regarding hardcoded session keys.
  hunt_leads:
    - lead: Monitor web logs for frequent changes or unexpected manual authorization in administrative dashboards not correlated with legitimate user activity.
      technique_id: T1189
      data_needed:
        - webserver access logs
        - application audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The ability to forge administrator sessions bypasses standard authentication.
  mitigation_plan:
    - priority: immediate
      action: Change the default session encryption key in application/config/config.php.
      owner: IT Operations
      addresses: CVE-2026-87929
      evidence: Source explicitly identifies the file and vulnerability as a hardcoded key.
---

MaxSite CMS versions up to and including 109.6 are vulnerable to an authentication bypass due to a hardcoded session encryption key stored in the application/config/config.php file. Because this key remains static across all installations, an unauthenticated remote attacker can reconstruct the session cookie structure. By computing an HMAC-SHA1 signature using the discovered key, an attacker can generate a forged 'ci_session' cookie that grants administrator privileges. This flaw effectively bypasses critical authentication and authorization checks within the application's core functions, specifically is_login() and mso_check_allow(). This vulnerability presents a critical risk as it allows full unauthorized control of the CMS administrative interface.

## Impact

Successful exploitation allows an unauthenticated remote attacker to gain full administrative access to the MaxSite CMS instance. This can lead to complete site takeover, unauthorized access to user data, modification of content, or the injection of malicious code into the web environment. The scope of targeting includes all public-facing instances of MaxSite CMS version 109.6 and below.

## Recommendation

Prioritized actions for security and IT teams:
- Upgrade MaxSite CMS to the latest version that remediates CVE-2026-87929.
- Review web server access logs for anomalous session cookie patterns, specifically 'ci_session' tokens that differ in structure or origin from established baseline traffic.
- Audit the 'application/config/config.php' file on all deployed instances to verify if a unique, site-specific encryption key has been configured, overriding the default.
