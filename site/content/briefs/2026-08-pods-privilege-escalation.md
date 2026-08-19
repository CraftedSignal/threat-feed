---
title: 'CVE-2026-19598: Authorization Bypass in Pods Plugin for WordPress'
slug: 2026-08-pods-privilege-escalation
description: The Pods plugin for WordPress contains an authorization bypass in its AJAX router that allows unauthenticated attackers to escalate privileges or take over administrative accounts.
date: "2026-08-15T18:19:56Z"
lastmod: "2026-08-19T04:16:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=76664995-C080-59C6-A771-147DEC084BFD&utm_source=rss&utm_medium=rss
vendors:
  - WordPress
products:
  - Pods – Custom Content Types and Fields
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation of Privilege Escalation Vulnerability
    evidence: This makes it possible for unauthenticated attackers to escalate their privileges to Administrator or overwrite the password of any user account.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595.002
    technique_name: Vulnerability Scanning
    evidence: The vulnerability exists because the pods_admin AJAX router funnels every access check... through pods_error().
    confidence_band: high
cves:
  - id: CVE-2026-19598
    cvss: 9.8
    epss: 0.00427
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19598
  - https://sploitus.com/exploit?id=76664995-C080-59C6-A771-147DEC084BFD&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Pods plugin on all WordPress instances
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in versions <= 3.3.9
  hunt_leads:
    - lead: Search web logs for anomalous admin-ajax.php requests
      technique_id: T1068
      data_needed:
        - web server access logs
        - PHP error logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation leverages the pods_admin AJAX router
  mitigation_plan:
    - priority: immediate
      action: Patch plugin
      owner: IT Operations
      addresses: CVE-2026-19598
      evidence: Official CVE entry
updates:
  - at: "2026-08-19T04:16:54Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=76664995-C080-59C6-A771-147DEC084BFD&utm_source=rss&utm_medium=rss
---

The Pods - Custom Content Types and Fields plugin for WordPress is vulnerable to a critical privilege escalation and authorization bypass (CVE-2026-19598) affecting all versions up to and including 3.3.9. The vulnerability originates in the pods_admin AJAX router, which handles security checks such as nonce verification, authentication, and capability gates. Due to a design flaw in the meta-box-loader compatibility path, the plugin calls pods_error() upon failing security checks. Critically, instead of terminating the request, the function logs the error and returns false, allowing the execution flow to continue unchecked. An unauthenticated attacker can exploit this behavior to perform unauthorized administrative actions, including changing user passwords or escalating privileges to Administrator, ultimately leading to complete site takeover.

## Attack Chain

1. Attacker identifies a target WordPress site running the Pods plugin version 3.3.9 or earlier.
2. Attacker crafts an HTTP request targeting the pods_admin AJAX endpoint (typically wp-admin/admin-ajax.php).
3. Attacker directs the request to utilize the vulnerable meta-box-loader compatibility path.
4. Attacker omits or provides invalid security tokens (nonces) or credentials, triggering a validation failure.
5. The plugin executes the pods_error() function, which records the failure to the PHP error log but fails to kill the script execution.
6. The application continues execution as if the request were authorized.
7. Attacker submits parameters intended for an administrative action, such as a user password change or role update.
8. The application processes the administrative request, resulting in site takeover or account compromise.

## Impact

Successful exploitation allows unauthenticated attackers to bypass all security guards in the affected plugin. This enables unauthorized account creation, modification of user passwords (including the administrator account), and the execution of arbitrary administrative functions. Depending on the site configuration, this likely leads to full site compromise and persistent access for the threat actor.

## Recommendation

* Update the Pods - Custom Content Types and Fields plugin to the latest version immediately to patch CVE-2026-19598.
* Monitor web server error logs for unexpected calls to pods_error() or evidence of pods_admin execution from unauthenticated sessions.
* Review WordPress user account modifications and administrative role changes for anomalous activity during the relevant timeframe.
