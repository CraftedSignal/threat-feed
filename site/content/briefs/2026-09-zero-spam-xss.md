---
title: Stored XSS in Zero Spam for WordPress Plugin
slug: 2026-09-zero-spam-xss
description: An unauthenticated Stored Cross-Site Scripting vulnerability in Zero Spam for WordPress (CVE-2026-96752) allows attackers to inject malicious scripts into logs via nested POST array keys in Contact Form 7 submissions.
date: "2026-09-25T08:59:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zero_spam_for_wordpress:zero_spam_for_wordpress:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - xss
  - wordpress
  - cve-2026-96752
vendors:
  - WordPress
products:
  - Zero Spam for WordPress (<= 5.7.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: This allows for potential session hijacking or further unauthorized actions within the WordPress dashboard.
    confidence_band: high
cves:
  - id: CVE-2026-96752
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96752
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Zero Spam for WordPress plugin to version > 5.7.10
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-96752 vulnerability disclosure
  hunt_leads:
    - lead: Audit 'zerospam_log' database table for HTML/JS strings
      technique_id: T1189
      data_needed:
        - Database logs or direct inspection of wp_zerospam_log table
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The payload is stored verbatim in the zerospam_log.submission_data column
  mitigation_plan:
    - priority: immediate
      action: Patch WordPress plugin to version > 5.7.10
      owner: IT Operations
      addresses: CVE-2026-96752
      evidence: NVD vulnerability disclosure
---

The Zero Spam for WordPress plugin, versions 5.7.10 and earlier, contains a critical Stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-96752. The issue stems from insufficient input sanitization and output escaping when processing data submitted via Contact Form 7. An unauthenticated attacker can exploit this by submitting a request containing a crafted nested POST array key. If the plugin's security features flag the submission as spam, the malicious payload is stored verbatim in the 'zerospam_log' database table within the 'submission_data' column. When an administrative user views the submission logs in the WordPress dashboard, the injected script executes in the context of the administrator's session. This vulnerability poses a significant risk, as it allows attackers to potentially hijack sessions, perform unauthorized administrative actions, or inject further malicious content into the WordPress environment.

## Attack Chain

1. Attacker identifies a WordPress site utilizing both the Zero Spam for WordPress plugin and Contact Form 7.
2. Attacker crafts an HTTP POST request targeting the Contact Form 7 endpoint.
3. Attacker embeds a malicious JavaScript payload within a nested POST array key (e.g., fieldname[subfield]=&lt;script>alert(1)&lt;/script>).
4. Attacker submits the form without the mandatory 'zerospam_david_walsh_key' field to ensure the request is flagged as spam.
5. The Zero Spam plugin intercepts the request and saves the malicious input into the 'zerospam_log' database table.
6. A WordPress administrator accesses the Zero Spam plugin dashboard to review flagged spam submissions.
7. The administrator's browser renders the logged submission data, triggering the execution of the injected JavaScript payload.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the browser of a WordPress administrator. This can lead to full site compromise, session theft, unauthorized data access, or the creation of rogue administrative accounts, impacting any WordPress site where the affected plugin is configured to monitor Contact Form 7 submissions.

## Recommendation

Prioritized, concrete actions for security teams:
- Immediately update the Zero Spam for WordPress plugin to a version released after 5.7.10 that addresses CVE-2026-96752.
- Implement a Web Application Firewall (WAF) rule to inspect and block POST requests containing non-alphanumeric characters or script tags in nested array keys targeted at WordPress form endpoints.
- Review administrative access logs and the Zero Spam submission log entries for suspicious script injections or unexpected outbound connections occurring after form submissions.
- Apply the principle of least privilege by auditing WordPress user accounts and ensuring administrative access is restricted to verified personnel only.
