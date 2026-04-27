---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence After Takedown
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA PhaaS platform, which facilitates MFA bypass and email account compromise, experienced a temporary decrease in activity following a takedown in March 2026, but campaign volumes and TTPs quickly returned to pre-disruption levels, indicating the actors behind the platform remain active and adaptive.
date: "2026-03-30T23:00:57Z"
severities:
  - high
tags:
  - phishing
  - credential-theft
  - phishing-as-a-service
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
references:
  - https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/
rules:
  - title: Detect Suspicious JavaScript for Cookie Extraction
    description: Detects JavaScript code potentially used for extracting session cookies after CAPTCHA validation.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
  - title: Detect Proxying Credentials to Microsoft 365 via JavaScript
    description: Detects JavaScript code proxying credentials to Microsoft 365 cloud account, indicative of credential harvesting.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On March 4, 2026, Europol disrupted the Tycoon2FA PhaaS platform, seizing 330 domains that formed its core infrastructure. This platform, active since 2023, allows cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts. In mid-2025, Tycoon2FA was reportedly responsible for 62% of all phishing attempts blocked by Microsoft, generating over 30 million malicious emails in a single month. Despite the takedown, CrowdStrike observed only a short-term decrease in…
