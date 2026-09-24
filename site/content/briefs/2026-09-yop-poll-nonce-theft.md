---
title: Account Takeover via Origin Validation Error in YOP Poll WordPress Plugin
slug: 2026-09-yop-poll-nonce-theft
description: The YOP Poll plugin for WordPress, in versions up to 7.0.10, exposes REST nonces via postMessage to window.opener, enabling attackers to perform unauthorized administrative actions including account takeover.
date: "2026-09-24T10:46:42Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:yop-poll:yop_poll:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - plugin
  - account-takeover
  - vulnerability
vendors:
  - WordPress
products:
  - YOP Poll (<= 7.0.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The Administrator must open an attacker-controlled page in order to exploit this vulnerability.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This makes it possible for unauthenticated attackers to steal a REST nonce scoped to a logged-in Administrator and use it to change the Administrator's email address and password, resulting in full account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-85682
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85682
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade YOP Poll plugin to the patched version beyond 7.0.10
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-85682 vulnerability in versions <= 7.0.10
  mitigation_plan:
    - priority: immediate
      action: Upgrade YOP Poll to the latest available version
      owner: IT Operations
      addresses: CVE-2026-85682
      evidence: NVD vulnerability notice
---

The YOP Poll plugin for WordPress is vulnerable to an origin validation error (CVE-2026-85682) in all versions up to and including 7.0.10. The vulnerability stems from the plugin's improper use of the postMessage() API, which transmits a wp_rest nonce to the window.opener object using a wildcard targetOrigin. By exploiting this, an unauthenticated attacker can orchestrate a cross-origin attack against a logged-in Administrator. If an Administrator is induced to visit an attacker-controlled website, the attacker can intercept the transmitted nonce. With this REST nonce, the attacker gains the ability to make authenticated requests on behalf of the Administrator, specifically allowing them to modify administrative credentials, change the associated email address, and achieve a full account takeover of the WordPress instance. This vulnerability highlights the risks associated with improper cross-window communication in web plugins.

## Attack Chain

1. Attacker hosts a malicious webpage containing a crafted JavaScript payload.
2. Attacker crafts a phishing campaign or uses social engineering to lure an authenticated WordPress Administrator to the malicious webpage.
3. The malicious webpage opens a new window or tab pointing to the target WordPress site's YOP Poll component.
4. The YOP Poll plugin executes, sending a message containing the sensitive 'wp_rest' nonce via postMessage() to the opener.
5. The attacker's malicious script intercepts the window.opener.postMessage event due to the wildcard origin configuration.
6. Attacker extracts the valid 'wp_rest' nonce from the message object.
7. Attacker uses the stolen nonce to authenticate REST API calls directed at the WordPress backend.
8. Attacker updates the Administrator's user profile, changing the email address and password to finalize account takeover.

## Impact

Successful exploitation allows for full administrative account takeover. This gives the attacker complete control over the WordPress instance, enabling them to modify content, install malicious plugins, exfiltrate database contents, or deploy additional malware. The scope is limited to WordPress installations utilizing YOP Poll version 7.0.10 or earlier.

## Recommendation

Prioritize the remediation of CVE-2026-85682 by updating the YOP Poll plugin to the latest version patched by the vendor. Ensure that administrative users are encouraged to maintain session hygiene and avoid navigating to untrusted external sites while holding an active, elevated session in the WordPress dashboard.
