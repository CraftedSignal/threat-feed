---
brief_id: brief-2026-11-01-whitearmor-amplifai
event_id: brief-2026-11-01-whitearmor-amplifai
revision: 1
activity_at: "2026-11-01T23:00:52Z"
title: 'Whitearmor Ransomware: Data Breach of AmplifAI GoDaddy Instance'
slug: 2026-11-whitearmor-amplifai
description: The Whitearmor ransomware group exfiltrated a large-scale employee database, login logs, and operational rosters from a GoDaddy AmplifAI instance, exposing Okta SSO and Office 365 federation details.
date: "2026-11-01T23:00:52Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Whitearmor
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: almost certain
qa_status:
  verdict: pass
  validation_status: Data points verified against the provided source text.
tags:
  - ransomware
  - data-theft
  - identity
  - cloud
vendors:
  - AmplifAI
  - GoDaddy
products:
  - AmplifAI (GoDaddy instance)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The stolen data includes an employee database containing over 13,500 records, login logs, roster data, and details regarding GoDaddy call center programs.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: The threat actors have published the exfiltrated database files on their Tor leak site.
    confidence_band: high
references:
  - https://www.ransomware.live/group/Whitearmor
iocs:
  - type: url
    value: http://whitearz6uvtfdefgsc4r3mzmyswtte65k5umcmv6cu6zhi4l5k4irad.onion
ioc_counts:
  url: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Identity Team
  immediate_actions:
    - action: Check Okta audit logs for anomalous logins related to App ID exksdlj2ty3Pfq9En0x7
      owner: Identity Team
      due: 24h
      evidence: 'Okta App ID: exksdlj2ty3Pfq9En0x7 (AmplifAI)'
  hunt_leads:
    - lead: Hunt for credential stuffing attempts or unusual API authentication calls to the GoDaddy Okta /api/v1/authn endpoint.
      technique_id: T1110
      data_needed:
        - Okta System Log
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'Authn API: POST https://godaddy.okta.com/api/v1/authn (accepts JSON {username, password})'
  mitigation_plan:
    - priority: immediate
      action: Rotate all credentials for users identified in the leaked database as having non-default passwords.
      owner: IT Operations
      addresses: Credential theft
      evidence: 13,510 default passwords vs 9 non-default passwords
---

The Whitearmor ransomware group has claimed a successful breach of an AmplifAI instance used by GoDaddy. The actors exfiltrated a significant volume of data, including a database of 13,565 employees, operational rosters, and login logs detailing device usage and access locations. The leak confirms that the compromised instance is integrated with the GoDaddy Okta tenant, providing specific application IDs and federation metadata for Okta and Office 365. This presents a high risk of credential stuffing or session hijacking against the affected identity providers.

## Impact
The exfiltrated dataset contains sensitive employee information (names, emails, employee IDs, and password hashes/states) for over 13,500 individuals. Additionally, the exposure of Okta SSO and O365 federation parameters creates a direct risk for identity-based attacks targeting GoDaddy corporate systems.

## Recommendation
- Review Okta and Office 365 logs for anomalous access originating from accounts identified in the leaked database.
- Revoke and rotate credentials for any accounts found with non-default passwords in the leaked 'all_users.json' file.
- Monitor for unauthorized OIDC/SAML application access attempts utilizing the exfiltrated Application IDs (e.g., exksdlj2ty3Pfq9En0x7).
- Implement or enforce phishing-resistant Multi-Factor Authentication (MFA) for the identified GoDaddy Okta tenant.
