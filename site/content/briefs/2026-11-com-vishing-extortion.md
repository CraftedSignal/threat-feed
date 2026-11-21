---
brief_id: brief-2026-11-21-com-vishing-extortion
event_id: brief-2026-11-21-com-vishing-extortion
revision: 1
activity_at: "2026-11-21T02:05:07Z"
title: Com-Affiliated Vishing and Cloud Data Extortion Campaigns
slug: 2026-11-com-vishing-extortion
description: Com-affiliated threat actors are leveraging vishing and adversary-in-the-middle (AiTM) proxies to harvest credentials and multi-factor authentication (MFA) tokens for data exfiltration and extortion.
date: "2026-11-21T02:05:07Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Bling Libra
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://unit42.paloaltonetworks.com/com-affiliate-vishing-attacks/
  observed_at: "2026-11-21T02:05:07Z"
  confidence: medium
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
tags:
  - vishing
  - extortion
  - social-engineering
references:
  - https://unit42.paloaltonetworks.com/com-affiliate-vishing-attacks/
---

### Overview
Unit 42 has tracked persistent vishing campaigns conducted by Com-affiliated threat actors since August 2026, targeting financial, healthcare, and legal sectors primarily in the U.S., UK, and Australia. The actors utilize social engineering and AiTM proxy infrastructure to bypass authentication and exfiltrate sensitive data from cloud collaboration platforms for extortion.

### Attack Chain
- **Initial Access:** Actors perform vishing, impersonating internal IT support to direct victims to organization-specific subdomains that serve as AiTM proxies.
- **Credential Access:** The AiTM proxies intercept credentials and MFA approvals in real-time. Actors may enroll their own unauthorized MFA devices or replay persistent session tokens.
- **Persistence:** Actors establish access through unauthorized MFA device enrollment, cloud infrastructure credentials, and the authorization of third-party OAuth applications.
- **Exfiltration:** Data is exfiltrated from Microsoft 365, OneDrive, and SharePoint using native SaaS and REST APIs, scripted HTTP requests, or cloud storage tools.
- **Browser Implantation:** Certain activity clusters deploy malicious Chromium-based browser extensions to perform keylogging, screen capture, and command-and-control functions via the Chrome DevTools Protocol.
- **Extortion:** Actors send direct messages via internal email or Microsoft Teams to victims, notifying them of the data breach and directing them to Tor-hosted negotiation sites.

### Impact
Victims suffer unauthorized access to high-impact corporate data, including financial records, patient data, client agreements, and confidential casework, which are subsequently held for extortion.

### Recommendation
- Tighten help desk verification processes.
- Transition to phishing-resistant MFA (FIDO2/passkeys).
- Implement browser extension allowlists.
- Establish visibility into identity actions and alert on unauthorized data exports.
