---
brief_id: brief-2026-03-30-tycoon2fa-resurgence
event_id: brief-2026-03-30-tycoon2fa-resurgence
revision: 2
activity_at: "2026-03-30T07:31:18Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:04f352bcb19c21389b810e386fd3895c4e569b89f9e98a230e19b62ede57d211
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Tycoon2FA PhaaS Resurgence After Takedown
slug: 2026-03-30-tycoon2fa-resurgence
description: The Tycoon2FA PhaaS platform, which facilitates MFA bypass and email account compromise, experienced a temporary decrease in activity following a takedown operation, but campaign volumes have since returned to pre-disruption levels, and TTPs remain consistent.
date: "2026-03-30T07:31:18Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - phishing
  - credential-theft
  - mfa-bypass
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/
rules:
  - title: Detect Tycoon2FA Phishing Pages
    description: Detects access to fake Microsoft 365 or Google login pages hosted on Tycoon2FA domains, indicating a phishing attempt.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: Detect Credential Proxying via Obfuscated JavaScript
    description: Detects the use of obfuscated JavaScript files to proxy credentials to a legitimate Microsoft 365 cloud account.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1059.007
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On March 4, 2026, Europol announced the disruption of the Tycoon2FA PhaaS platform, which enabled cybercriminals to bypass MFA and compromise email accounts. This takedown involved seizing 330 domains. However, CrowdStrike observed a short-term decrease in activity followed by a return to pre-disruption levels, with consistent TTPs. Tycoon2FA began operations in 2023 and was responsible for 62% of all phishing attempts blocked by Microsoft in mid-2025, purportedly generating over 30 million malicious emails in a single month. The resurgence indicates the actors remain active and adaptive, requiring continued vigilance and advanced detection capabilities. This platform is a clear example of how adversaries are persistent in pursuing their objectives and will find ways to maintain pressure on defenders.

## Attack Chain

1.  The attack begins with a phishing email delivered to the victim, enticing them to click on a link.
2.  The link redirects the victim to a Tycoon2FA CAPTCHA page to evade automated detection.
3.  Upon successful CAPTCHA validation, the victim is redirected to a fake Microsoft 365 or Google login page hosted on a Tycoon2FA domain.
4.  The fake login page prompts the user to enter their credentials.
5.  Victim's credentials are then proxied to a legitimate Microsoft 365 cloud account via an obfuscated JavaScript file.
6.  The JavaScript file extracts the victim’s email address.
7.  Session cookies are stolen upon CAPTCHA validation.
8.  The attacker authenticates to the victim’s cloud environment using the stolen cookies and credentials, gaining access to their account.

## Impact

Tycoon2FA was responsible for 62% of all phishing attempts blocked by Microsoft in mid-2025 and generated over 30 million malicious emails in a single month. The platform's resurgence after a takedown indicates its operators' resilience and ability to adapt. Successful attacks lead to unauthorized access to email accounts, data exfiltration, and potential further compromise of other systems and services. Victims can experience significant financial loss and reputational damage due to the compromise of sensitive information.

## Recommendation

*   Monitor network traffic for connections to newly registered domains, as threat actors may reconstitute their infrastructure in the wake of disruptions.
*   Deploy the Sigma rule `Detect Tycoon2FA Phishing Pages` to identify potential phishing attempts leveraging fake login pages.
*   Implement detections for suspicious JavaScript execution within web pages, focusing on cookie theft and credential extraction as seen in the attack chain.
*   Monitor authentication logs for unusual login patterns or access from unexpected geographic locations, particularly after CAPTCHA validation.
