---
title: Palo Alto Networks Recruiting Impersonation Phishing Campaign
slug: 2026-03-panw-recruiting-scam
description: Since August 2025, threat actors have been impersonating Palo Alto Networks talent acquisition staff in a sophisticated phishing campaign targeting senior professionals, using social engineering tactics to solicit fraudulent resume fees.
date: "2026-03-25T12:00:00Z"
severities:
  - high
tags:
  - phishing
  - recruiting
  - social-engineering
  - scam
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1598
    technique_name: Phishing for Information
references:
  - https://unit42.paloaltonetworks.com/phishing-attackers-pose-as-panw-recruiters/
ioc_counts:
  email: 4
  phone: 2
rules:
  - title: Detect Recruiting Emails From Free Email Providers
    description: Detects emails that claim to be from a specific organization, but originate from free email providers like Gmail, which could indicate recruiting scams.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - email
      - o365
  - title: Detect Phishing Email Lures with ATS Mention
    description: Detects emails that mention Applicant Tracking Systems (ATS) in a suspicious context, potentially indicating a phishing attempt to solicit resume services.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - email
      - o365
rules_count: 2
---

Since August 2025, a series of phishing campaigns have impersonated Palo Alto Networks talent acquisition staff, targeting senior-level professionals. The attackers leverage scraped LinkedIn data to craft personalized lures, enhancing the credibility of their outreach. This campaign involves social engineering to manufacture a bureaucratic barrier related to the candidate's resume. The attackers falsely claim that the candidate's resume failed to meet the applicant tracking system (ATS)…
