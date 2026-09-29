---
title: West African Fraud Actors Targeting Universities via Compromised .edu Accounts
slug: 2026-09-west-african-edu-fraud
description: West African threat actors are leveraging compromised university email accounts to distribute job-based advance fee fraud by harvesting credentials via legitimate third-party form services.
date: "2026-09-29T10:23:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - phishing
  - fraud
  - advance-fee-fraud
  - higher-education
  - social-engineering
vendors:
  - Google
  - Wix
  - Jotform
  - Zoho
  - Microsoft
products:
  - Google Forms
  - Wix Forms
  - Jotform
  - Zoho Forms
  - Microsoft Office
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The initial lures aim to entice a wide range of university targets... The email directs the potential victim to fill out a web form on a third-party website.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: The recipient is directed to a web-based form... If the user fills out the form that usually asks for usernames, passwords, and personally identifiable information (PII), then that information is captured.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Enforce mandatory MFA for all faculty, staff, and student accounts.
      owner: IT Operations
      due: 72h
      evidence: Require the use of multifactor authentication (MFA) on all accounts.
  mitigation_plan:
    - priority: immediate
      action: Deploy email filtering blocks for unsolicited job opportunity lures containing links to third-party form builders.
      owner: SOC
      addresses: Phishing/Social Engineering
      evidence: Remain vigilant about unsolicited job offers, no matter the platform or application on which it is received.
---

Proofpoint researchers have identified a campaign by West African-based fraud actors targeting U.S. universities. The threat actors compromise .edu email accounts through credential harvesting lures, which they then use to distribute job-related advance fee fraud (AFF). The actors exploit the inherent trust associated with institutional email addresses to deceive students, staff, and alumni. 

Rather than deploying custom phishing kits, the actors utilize legitimate form-building services, including Google Forms, Wix, Jotform, Zoho Forms, and Microsoft Office, to capture credentials and personally identifiable information (PII). By avoiding the use of explicit keywords like "password" in form fields, attackers attempt to bypass simple automated filters. Once an account is compromised, it is used to send legitimate-looking emails detailing fake job opportunities. Victims are subsequently coerced into mobile check deposits and the purchase of gift cards. The threat actors exhibit aggressive tactics, including threats of legal action and impersonation of law enforcement, if targets fail to comply with the financial demands.

## Attack Chain

1. Attacker sends a phishing email to university targets claiming an account must be refreshed due to graduation or retirement.
2. The email redirects the victim to a legitimate third-party form provider (e.g., Google Forms, Jotform).
3. The victim provides account credentials and PII into the hosted form, bypassing filters by following attacker instructions (e.g., using "WORDWORD" as a placeholder for password).
4. The actor logs into the victim's university account using the harvested credentials.
5. The compromised account is used to send bulk emails impersonating faculty or staff, advertising fake remote job opportunities.
6. Victims interact with a second set of malicious forms that harvest personal and financial details.
7. The actor engages the victim via email or phone, instructing them to deposit a fraudulent check and purchase gift cards for "employment" costs.
8. If the victim resists, the actor escalates to threats, impersonation of law enforcement, or harassment to force payment.

## Impact

The campaign facilitates significant financial loss for university-affiliated victims through advance fee fraud. Compromised university accounts are used to maintain persistence and establish credibility for broader scam distribution. The aggregation of PII allows for secondary identity theft and more targeted future social engineering. While the number of victims is not explicitly stated, the broad nature of the campaign indicates a high-volume attempt to leverage institutional trust.

## Recommendation

Prioritized actions for security teams to mitigate this threat:

- Enforce mandatory multi-factor authentication (MFA) across all university accounts to prevent account takeover via credential phishing.
- Implement email filtering policies that flag or block emails containing links to common third-party form builders when sent from external sources or suspicious internal accounts.
- Educate the user base on the indicators of job-based advance fee fraud, specifically the request for mobile check deposits followed by gift card purchases.
- Monitor for anomalous login behavior or mass-emailing activity originating from internal .edu accounts, which may indicate an account compromise.
- Investigate any reported "IT" communications that direct users to generic, third-party form-hosting websites rather than official university authentication portals.
