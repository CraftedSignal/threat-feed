---
title: 'CVE-2026-93775: Stored Cross-Site Scripting in Podlove Podcast Publisher'
slug: 2026-10-podlove-xss
description: The Podlove Podcast Publisher plugin for WordPress contains an unauthenticated Stored XSS vulnerability in the Auphonic Webhook implementation, allowing for arbitrary script injection via crafted POST requests.
date: "2026-10-10T07:51:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:podlove:podcast_publisher:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - wordpress
  - cve-2026-93775
vendors:
  - Podlove
products:
  - Podlove Podcast Publisher (<= 4.5.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can submit a crafted POST request to the webhook endpoint where the 'status_string' field is not 'Done', causing the raw POST data to be logged by the plugin.
    confidence_band: high
cves:
  - id: CVE-2026-93775
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93775
rules:
  - title: Detects CVE-2026-93775 Exploitation - Unauthenticated POST to Auphonic Webhook with Suspicious status_string
    description: Detects exploitation attempts targeting CVE-2026-93775 by identifying POST requests to the Auphonic webhook where the status_string field is not 'Done', which triggers the vulnerable logging mechanism.
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
    - IT Operations
  immediate_actions:
    - action: Upgrade Podlove Podcast Publisher to the latest version.
      owner: IT Operations
      due: 48h
      evidence: Plugin version 4.5.6 is vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Block or restrict access to the Auphonic Webhook endpoint if not in active use.
      owner: IT Operations
      addresses: CVE-2026-93775
      evidence: Source notes the webhook endpoint as the trigger for the vulnerable log storage.
---

The Podlove Podcast Publisher plugin for WordPress (versions 4.5.6 and earlier) is susceptible to a Stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-93775. The flaw originates in the plugin's Auphonic Webhook endpoint, which lacks sufficient input sanitization and output escaping. When an unauthenticated attacker sends a POST request to this endpoint containing a `status_string` field that does not equal 'Done', the plugin logs the entire raw POST superglobal data. Because this data is stored in the application logs without authentication key validation, malicious JavaScript payloads can be persisted. These scripts execute in the browser of any user who subsequently views the logs, enabling potential session hijacking, unauthorized administrative actions, or credential theft. Given that the attack requires no authentication, it represents a high-risk vector for WordPress deployments using the affected plugin.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary scripts in the context of an administrator or other user viewing the plugin logs. This can lead to the complete compromise of administrative accounts, unauthorized configuration changes, or the injection of further malicious content into the WordPress site.

## Recommendation

- Upgrade the Podlove Podcast Publisher plugin to the latest version beyond 4.5.6 immediately.
- Until patching is possible, restrict access to the webhook endpoint or disable the Auphonic Webhook feature if not required.
- Review WordPress access logs for anomalous POST requests directed at the plugin's webhook endpoint that deviate from expected patterns.
