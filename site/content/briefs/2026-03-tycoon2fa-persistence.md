---
title: Tycoon2FA Phishing-as-a-Service Platform Persists After Takedown
slug: 2026-03-tycoon2fa-persistence
description: The Tycoon2FA phishing-as-a-service (PhaaS) platform, used to bypass MFA and compromise email accounts, saw a temporary decrease in activity after a law enforcement takedown, but cloud compromises have since returned to pre-disruption levels with unchanged TTPs, indicating continued threat actor activity.
date: "2026-03-29T08:34:23Z"
severities:
  - high
tags:
  - phishing
  - credential-theft
  - cloud
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
  - title: Detect Connection to Tycoon2FA Domain
    description: Detects connections to domains associated with the Tycoon2FA Phishing-as-a-Service platform based on domain names.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
  - title: Detect JavaScript Email Address Extraction
    description: Detects process creation events indicative of JavaScript being used to extract email addresses, a technique used by Tycoon2FA.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On March 4, 2026, Europol announced a technical disruption of Tycoon2FA, a subscription-based phishing-as-a-service (PhaaS) platform enabling cybercriminals to bypass MFA and compromise email accounts. The takedown involved seizing 330 domains. Despite this disruption, CrowdStrike observed only a short-term decrease in Tycoon2FA campaign activity. The volume of cloud compromises has since returned to pre-disruption levels, and Tycoon2FA’s tactics, techniques, and procedures (TTPs) remain…
