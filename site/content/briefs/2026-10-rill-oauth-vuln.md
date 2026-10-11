---
title: Missing Authorization Vulnerability in Rill Admin OAuth Server
slug: 2026-10-rill-oauth-vuln
description: Rill versions 0.77.0 through 0.90.5 contain a missing authorization vulnerability that allows attackers to obtain non-expiring API tokens with elevated permissions via unauthorized OAuth code issuance.
date: "2026-10-11T14:01:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rilldata:rill:0.77.0:*:*:*:*:*:*:*
  - cpe:2.3:a:rilldata:rill:0.90.5:*:*:*:*:*:*:*
vendors:
  - Rill
products:
  - Rill (0.77.0-0.90.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can lure a user to an authorization link, obtaining a non-expiring API token with the user's full permissions.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550.001
    technique_name: 'Use Alternate Authentication Material: Application Access Token'
    evidence: Attackers can obtain a non-expiring API token with the user's full permissions.
    confidence_band: high
cves:
  - id: CVE-2026-108718
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108718
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Rill to version 0.90.6 or higher
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-108718 remediation
  hunt_leads:
    - lead: Search authentication logs for suspicious OAuth registrations or token issuance events
      technique_id: T1550.001
      data_needed:
        - Rill application logs regarding client registration
        - OAuth audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Missing authorization vulnerability in admin OAuth server
  mitigation_plan:
    - priority: immediate
      action: Upgrade Rill to 0.90.6 or later
      owner: IT Operations
      addresses: CVE-2026-108718
      evidence: NVD vulnerability disclosure
---

Rill versions 0.77.0 through 0.90.5 are affected by a missing authorization vulnerability within the admin OAuth server component. This flaw permits the dynamic registration of OAuth clients that can request elevated scopes, such as long_lived_access_token, without obtaining explicit user consent. An attacker can exploit this by registering a malicious client and tricking a legitimate user into visiting a crafted authorization link. Upon the user's interaction, the system issues a non-expiring API token directly to the attacker-controlled client, granting the attacker the user's full permissions. This vulnerability enables persistent access and potential exfiltration of sensitive analytics or metadata managed within the Rill environment. Organizations utilizing Rill versions 0.77.0 to 0.90.5 are at risk of complete account takeover if users interact with attacker-supplied authorization links.

## Impact

Successful exploitation results in the unauthorized generation of non-expiring API tokens, granting attackers persistent access to user data and Rill platform resources. This can lead to significant data exfiltration, unauthorized modification of analytics configurations, and loss of environment control. The severity is highlighted by a CVSS v3.1 base score of 8.1, reflecting high potential for unauthorized access and privilege escalation.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:
* Upgrade all instances of Rill to a version beyond 0.90.5 immediately to patch CVE-2026-108718.
* Audit OAuth client registrations in Rill administrative logs for any unexpected or dynamically registered client IDs initiated during the period of exposure.
* Review logs for OAuth authorization requests where the requested scope includes long_lived_access_token and the client was not pre-approved or vetted by administrative policy.
* Implement stricter access control policies for dynamic client registration to prevent unauthorized third-party integrations.
