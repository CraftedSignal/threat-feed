---
title: HeyForm CORS Misconfiguration Enabling Unauthorized GraphQL Access
slug: 2026-08-heyform-cors-vuln
description: HeyForm versions prior to 3.0.0-rc.8 are vulnerable to a CORS misconfiguration that allows cross-origin authentication, potentially leading to unauthorized data access or account modification.
date: "2026-08-28T23:35:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:heyform:heyform:*:*:*:*:*:*:*:*
vendors:
  - HeyForm
products:
  - HeyForm (< 3.0.0-rc.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can execute authenticated GraphQL queries from malicious pages visited by logged-in users.
    confidence_band: high
cves:
  - id: CVE-2026-82291
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82291
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade HeyForm to version 3.0.0-rc.8 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82291 vendor patch availability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade HeyForm to 3.0.0-rc.8 or later
      owner: IT Operations
      addresses: CVE-2026-82291
      evidence: NVD vulnerability advisory
---

HeyForm versions prior to 3.0.0-rc.8 contain a security vulnerability (CVE-2026-82291) related to Cross-Origin Resource Sharing (CORS) implementation. The application improperly reflects the request 'Origin' header in its CORS responses while explicitly allowing credentials (Access-Control-Allow-Credentials: true). This configuration permits malicious websites to make authenticated cross-origin requests to the HeyForm instance on behalf of a logged-in user. By enticing an authenticated user to visit an attacker-controlled page, an adversary can execute unauthorized GraphQL queries. This allows for the exfiltration of sensitive information, including workspaces, project details, forms, and respondent submissions. Furthermore, attackers can leverage this vulnerability to modify account settings or perform other actions within the victim's session, significantly impacting user privacy and data integrity.

## Impact

The vulnerability poses a severe risk to organizations using self-hosted or managed HeyForm instances. Successful exploitation allows for unauthorized access to sensitive business data, including form submission results and respondent personally identifiable information (PII). Attackers may also modify account configurations or project settings, leading to potential service disruption or long-term persistence in the victim's account.

## Recommendation

* Upgrade HeyForm to version 3.0.0-rc.8 or later immediately to patch the CORS policy configuration.
* Audit web server or application logs for requests originating from unrecognized or suspicious domains that contain sensitive GraphQL endpoints.
* Restrict CORS 'Access-Control-Allow-Origin' headers to a strict, pre-approved list of domains rather than reflecting the request 'Origin' header.
