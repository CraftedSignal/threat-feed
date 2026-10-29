---
brief_id: brief-2026-10-29-anthropic-phishing
event_id: brief-2026-10-29-anthropic-phishing
revision: 1
activity_at: "2026-10-29T15:52:40Z"
title: Credential phishing campaign abusing AI themes and CAPTCHA evasion
slug: 2026-10-anthropic-phishing
description: Since September 2026, threat actors have leveraged fake Anthropic AI preview invitations, abused legitimate services, and utilized multi-layer CAPTCHA bypasses to harvest Google and Microsoft credentials.
date: "2026-10-29T15:52:40Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - phishing
  - credential-harvesting
  - social-engineering
  - cloud
vendors:
  - Google
  - Microsoft
  - GoTo
  - Zapier
  - Cloudflare
products:
  - Google Workspace
  - Microsoft 365
  - GoTo Webinar
  - Zapier URL Shortener
  - Cloudflare CAPTCHA
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: Threat actors abuse legitimate services, URL shorteners, and multiple CAPTCHAs to bypass traditional email security defenses and redirect victims to convincing Google and Microsoft login pages designed to steal credentials.
    confidence_band: high
references:
  - https://cofense.com/blog/would-your-employees-join-a-fake-anthropic-ai-preview
  - https://www.threathq.com/active-threat-reports/m-423868
  - https://www.threathq.com/active-threat-reports/m-423866
  - https://www.threathq.com/active-threat-reports/m-423475
iocs:
  - type: domain
    value: us968web-zoom.us
  - type: domain
    value: goo.gle-access-eventregister.icu
ioc_counts:
  domain: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block identified domains and hunt for traffic logs associated with these domains.
      owner: SOC
      due: 24h
      evidence: Cofense active threat report findings.
  hunt_leads:
    - lead: Identify emails containing links to URL shorteners redirected to domains with suspicious subdomains (e.g., -zoom, -access, -register).
      technique_id: T1566.002
      data_needed:
        - Email gateway logs
        - Web proxy logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Campaign utilizes URL shorteners and deceptive subdomains.
---

A credential phishing campaign identified by Cofense targets organizations with invitations to a fraudulent "Anthropic AI" private preview. The campaign successfully bypasses standard email security by abusing trusted platforms including GoTo Webinar, Zapier, and Cloudflare. The infrastructure utilizes multiple CAPTCHA challenges to impede automated sandbox analysis and credential harvesting pages designed to impersonate Google and Microsoft authentication portals.

## Attack Chain
1. Initial outreach via an email appearing to come from GoTo Webinar claiming to offer an exclusive Anthropic AI preview.
2. The email contains a link shortened through a legitimate service (Zapier) to evade email filtering.
3. Clicking the link triggers a Cloudflare CAPTCHA to verify the visitor.
4. The victim is redirected to a spoofed Zoom-branded meeting registration page.
5. The victim interacts with the registration form and selects "Continue with Google" or "Continue with Microsoft".
6. A custom CAPTCHA slider appears to block automated scanners and VPN traffic.
7. A spoofed credential harvesting page captures the user email or login information.

## Impact
Successful phishing leads to the compromise of corporate identity credentials, allowing attackers to access sensitive documentation or use the account for further internal infiltration.

## Recommendation
- Block the identified malicious domains at the web proxy and DNS levels.
- Implement email authentication controls (DMARC/SPF/DKIM) to protect your domain and improve visibility into spoofed sender activity.
- Advise employees to manually inspect URL domains for mismatches rather than relying on the branding present in the email or landing page.
- Evaluate web filtering solutions that allow for browser isolation or manual analysis of sites that employ multi-stage CAPTCHA redirects.
