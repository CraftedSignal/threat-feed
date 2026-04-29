---
title: Palo Alto Networks Recruiting Impersonation Phishing Campaign
slug: 2026-03-panw-recruiting-scam
description: Since August 2025, threat actors have been impersonating Palo Alto Networks talent acquisition staff in a sophisticated phishing campaign targeting senior professionals, using social engineering tactics to solicit fraudulent resume fees.
date: "2026-03-25T12:00:00Z"
type: coverage
types:
  - coverage
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
iocs:
  - type: email
    value: paloaltonetworks@gmail[.]com
  - type: email
    value: recruiter.paloalnetworks@gmail[.]com
  - type: email
    value: phillipwalters006@gmail[.]com
  - type: email
    value: posunrayi994@gmail[.]com
  - type: phone
    value: "+2349131397140"
  - type: phone
    value: +972 541234567
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

Since August 2025, a series of phishing campaigns have impersonated Palo Alto Networks talent acquisition staff, targeting senior-level professionals. The attackers leverage scraped LinkedIn data to craft personalized lures, enhancing the credibility of their outreach. This campaign involves social engineering to manufacture a bureaucratic barrier related to the candidate's resume. The attackers falsely claim that the candidate's resume failed to meet the applicant tracking system (ATS) requirements. They then offer to assist the candidate in acquiring a position for a fee, typically ranging from $400 to $800 for services like "executive ATS alignment" or "end-to-end executive rewrite." The goal is to exploit the candidate's professional ambitions by creating a sense of financial urgency and directing them to a third-party "expert" for paid services.

## Attack Chain

1. **Initial Outreach:** Attackers send personalized emails posing as Palo Alto Networks talent acquisition staff, using flattering language and details from the victim's LinkedIn profile.
2. **Establish Rapport:** The emails use legitimate company logos and signatures to appear authentic and build trust with the targeted professional.
3. **Manufactured Crisis:** Attackers claim the candidate's resume failed to meet ATS requirements, creating a bureaucratic barrier.
4. **Offer of Assistance:** The "recruiter" offers "executive ATS alignment" services for a fee, suggesting an urgent need to update the resume.
5. **Hand-off to "Expert":** The candidate is directed to a purported expert who provides structured service offers with specific price points (e.g., $400, $600, $800).
6. **Time Pressure:** The "recruiter" implies that the "review panel" has already begun, urging the candidate to update their CV within a limited timeframe.
7. **Payment Solicitation:** The "expert" offers to deliver the CV within hours, fitting the ostensible review window, but only after payment.
8. **Financial Exploitation:** Victims who comply with the demands pay for services that are never delivered, resulting in financial loss and potential identity theft.

## Impact

This phishing campaign targets senior-level professionals, aiming to defraud them of hundreds of dollars through fabricated resume services. Multiple incidents have been reported, indicating a widespread effort to exploit individuals seeking job opportunities. If successful, victims lose money and may expose personal information, potentially leading to further identity theft or fraudulent activities. The campaign undermines trust in legitimate recruiting processes and damages the reputation of Palo Alto Networks.

## Recommendation

*   Implement email filtering rules to flag messages from the IOC email addresses (paloaltonetworks@gmail[.]com, recruiter.paloalnetworks@gmail[.]com, phillipwalters006@gmail[.]com, posunrayi994@gmail[.]com).
*   Monitor network traffic and DNS queries for connections to domains resembling "paloaltonetworks" but with slight variations, as mentioned in the overview, and implement blocking where appropriate.
*   Educate employees and potential job candidates about this phishing scheme, emphasizing the importance of verifying recruiter identities and avoiding payment requests during the hiring process.
*   Deploy a Sigma rule to detect emails originating from free email providers (e.g. gmail.com) that claim to be from a specific organization based on email content and sender information (see rule below).
