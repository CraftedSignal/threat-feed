---
title: Authorization Bypass in WPMobile.App WordPress Plugin
slug: 2026-10-wpmobile-auth-bypass
description: An unauthenticated authorization bypass vulnerability in WPMobile.App (<= 11.82) allows attackers to exfiltrate password-reset URLs via the mail-to-push feature and perform account takeover.
date: "2026-10-02T10:23:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:wpmobile:wpmobile.app:*:*:*:*:*:wordpress:*:*
vendors:
  - WPMobile.App
products:
  - WPMobile.App – Android and iOS App Builder (<= 11.82)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: This makes it possible for unauthenticated attackers to exfiltrate password-reset URLs for arbitrary users, including administrators.
    confidence_band: high
cves:
  - id: CVE-2026-94541
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94541
rules:
  - title: Detects CVE-2026-94541 Exploitation - Access to WPMobile Push Queue
    description: Detects unauthenticated attempts to access the WPMobile.App push notification queue which may contain sensitive password reset URLs.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade WPMobile.App to version 11.83 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-94541 remediation
    - action: Disable 'mail-to-push' (wpmobile_auto_mail) in plugin settings
      owner: IT Operations
      due: 4h
      evidence: Vulnerability requires this feature to be enabled
  hunt_leads:
    - lead: Search web logs for unauthorized GET requests to /wp-json/wpmobile/ endpoints
      technique_id: T1555
      data_needed:
        - webserver access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Endpoint used to access the push queue
---

The WPMobile.App - Android and iOS App Builder plugin for WordPress is affected by an authorization bypass vulnerability identified as CVE-2026-94541. The vulnerability exists in all versions up to and including 11.82. It stems from improper authorization checks when handling internal plugin data. Specifically, when the plugin's 'mail-to-push' feature (wpmobile_auto_mail=1) is active, WordPress password-reset emails - which contain sensitive password-reset URLs and tokens - are incorrectly mirrored into a push notification queue. Because this queue lacks sufficient access controls, unauthenticated remote attackers can query the endpoint, extract the reset tokens for arbitrary accounts (including administrative accounts), and subsequently perform account takeover. This flaw represents a significant risk to WordPress sites utilizing this plugin for mobile app synchronization, as it grants attackers a direct path to privilege escalation.

## Attack Chain

1. Attacker identifies a WordPress site utilizing the WPMobile.App plugin with the 'mail-to-push' feature enabled.
2. Attacker triggers a password-reset request for an administrator account via the standard WordPress 'wp-login.php?action=lostpassword' endpoint.
3. WordPress generates a standard password-reset email containing the unique reset key and URL.
4. The vulnerable plugin intercepts the email and copies the content, including the sensitive reset URL, into the plugin's push notification queue.
5. Attacker makes an unauthenticated HTTP request to the vulnerable plugin endpoint designed to serve the push queue.
6. The plugin returns the contents of the queue, including the pending password-reset URL, due to a lack of authorization verification.
7. Attacker extracts the URL from the server response.
8. Attacker accesses the reset URL to set a new password for the administrator account, completing the account takeover.

## Impact

Successful exploitation allows unauthenticated attackers to gain full administrative access to compromised WordPress sites. This can lead to complete site compromise, data exfiltration, deployment of web shells, or redirection of site traffic to malicious domains. The scope is limited to WordPress installations running the affected plugin versions with the specific 'mail-to-push' configuration enabled.

## Recommendation

1. Upgrade the WPMobile.App - Android and iOS App Builder plugin to version 11.83 or higher immediately to remediate CVE-2026-94541.
2. If an immediate update is not possible, disable the 'mail-to-push' functionality within the plugin settings to prevent sensitive emails from being mirrored into the insecure queue.
3. Audit WordPress user accounts and review access logs for unusual password-reset activity originating from the plugin's API endpoints.
