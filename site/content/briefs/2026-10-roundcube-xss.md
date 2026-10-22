---
brief_id: brief-2026-10-22-roundcube-xss
event_id: brief-2026-10-22-roundcube-xss
revision: 1
activity_at: "2026-10-22T09:45:57Z"
title: 'Roundcube Webmail: Stored XSS and Injection (CVE-2026-48849)'
slug: 2026-10-roundcube-xss
description: CVE-2026-48849 is a stored XSS, HTML, and CSS injection vulnerability in Roundcube Webmail that enables malicious payload execution upon session restoration.
date: "2026-10-22T09:45:57Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*
vendors:
  - Roundcube
products:
  - Roundcube Webmail (< 1.6.16)
  - Roundcube Webmail (>= 1.7.0, < 1.7.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows attacker-controlled HTML, CSS, and JavaScript injected through the email subject field to be stored.
    confidence_band: high
cves:
  - id: CVE-2026-48849
    cvss: 4.4
    epss: 0.00261
    kev_status: "false"
references:
  - https://roundcube.net/news/2026/05/24/security-updates-1.6.16-and-1.7.1
  - https://github.com/roundcube/roundcubemail/releases/tag/1.6.16
  - https://github.com/roundcube/roundcubemail/releases/tag/1.7.1
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ANANDJOGAWADE-CVE-2026-48849-ROUNDCUBE-WEBMAIL-STORED-XSS
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ANANDJOGAWADE-CVE-2026-48849-ROUNDCUBE-WEBMAIL-STORED-XSS&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-48849 Exploitation Attempt
    description: Detects potential exploitation of CVE-2026-48849 by identifying script tags or CSS injection patterns in POST requests to Roundcube composition endpoints.
    platform: sigma
    severity: medium
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
    - SOC
  immediate_actions:
    - action: Patch Roundcube Webmail to 1.6.16 or 1.7.1.
      owner: IT Operations
      due: 48h
      evidence: Vendor security advisory for CVE-2026-48849.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Roundcube Webmail to 1.6.16 or 1.7.1
      owner: IT Operations
      addresses: CVE-2026-48849
      evidence: Vendor recommendation.
---

CVE-2026-48849 is a stored Cross-Site Scripting (XSS), HTML injection, and CSS injection vulnerability affecting Roundcube Webmail. The vulnerability resides in the handling of the email subject field during session restoration processes. An attacker can inject malicious payloads into an email subject; these payloads are stored within draft or session restoration data. When the targeted user logs back into the webmail interface, the stored payload executes automatically in the user's authenticated context.

## Attack Chain

1. Attacker crafts an email subject containing XSS, HTML, or CSS payloads.
2. Attacker logs into Roundcube Webmail and initiates a composition of a new message.
3. Attacker inputs the malicious payload into the "Subject" field.
4. Attacker triggers a background action (e.g., image attachment) to store the draft data.
5. Attacker forces an invalidation or expiration of the session while the session restoration data is cached.
6. Victim logs back into the Roundcube interface using valid credentials.
7. Roundcube attempts to restore the previous session, triggering the execution of the injected payload from the subject field.

## Impact

Successful exploitation allows for the execution of arbitrary JavaScript in the victim's session, DOM manipulation, visual defacement via CSS injection, and the creation of phishing overlays within the webmail interface. Payloads persist within the user's draft or session restoration data until removed.

## Recommendation

- Upgrade all Roundcube Webmail installations to version 1.6.16 or 1.7.1 immediately.
- Review web server access logs for anomalous POST requests to mail composition or draft-saving endpoints containing script tags or HTML/CSS injection metacharacters.
- Monitor webmail user activity for unexpected UI overlays or unusual script execution patterns following user logins.
