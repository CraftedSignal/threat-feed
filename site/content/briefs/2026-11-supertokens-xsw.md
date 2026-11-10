---
brief_id: brief-2026-11-10-supertokens-xsw
event_id: brief-2026-11-10-supertokens-xsw
revision: 1
activity_at: "2026-11-10T18:28:25Z"
title: 'SuperTokens Core: XML Signature Wrapping vulnerability (CVE-2026-123798)'
slug: 2026-11-supertokens-xsw
description: SuperTokens Core is vulnerable to XML Signature Wrapping (XSW) due to improper validation of SAML signatures, allowing authenticated users to impersonate other accounts.
date: "2026-11-10T18:28:25Z"
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
cpes:
  - cpe:2.3:a:supertokens:core:*:*:*:*:*:*:*:*
vendors:
  - SuperTokens
products:
  - SuperTokens Core (>= 11.3.0, < 11.3.7; >= 11.4.0, < 11.4.7; >= 12.0.0, < 12.0.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Core can therefore accept a cryptographically valid signature that references a different XML element from the Response or Assertion whose NameID and attributes are used for authentication.
    confidence_band: high
cves:
  - id: CVE-2026-123798
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123798
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade SuperTokens Core to 11.3.7, 11.4.7, or 12.0.10
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in versions 11.3.7, 11.4.7, and 12.0.10.
  hunt_leads:
    - lead: Analyze SAML authentication logs for malformed or unexpectedly large XML assertions
      technique_id: T1190
      data_needed:
        - SAML response XML blobs
        - Authentication service logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An ordinary user of the configured identity provider can move a genuinely signed element elsewhere in the document while supplying an attacker-authored identity-bearing element.
  mitigation_plan:
    - priority: immediate
      action: Apply software update to affected instances
      owner: IT Operations
      addresses: CVE-2026-123798
      evidence: The issue is fixed in versions 11.3.7, 11.4.7, and 12.0.10.
---

SuperTokens Core (versions >= 11.3.0, < 11.3.7; >= 11.4.0, < 11.4.7; >= 12.0.0, < 12.0.10) contains an XML Signature Wrapping (XSW) vulnerability. The application fails to apply the necessary `SAMLSignatureProfileValidator` before calling `OpenSAML` for signature verification. This allows an attacker to manipulate a SAML response by moving a valid signature to an attacker-controlled identity element, leading to successful impersonation of other identity provider users. The issue impacts both response-level and assertion-level signing paths.

## Impact

Successful exploitation allows an authenticated user to perform authentication bypass and assume the identity of another user within the system.

## Recommendation

- Upgrade SuperTokens Core to version 11.3.7, 11.4.7, 12.0.10, or later.
- Review authentication logs for anomalous account access patterns or rapid account switching by the same user session.
- Evaluate the necessity of SAML configurations that allow user-provided XML signatures if specific patching is delayed.
