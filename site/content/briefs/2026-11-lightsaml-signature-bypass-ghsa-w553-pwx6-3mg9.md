---
brief_id: brief-2026-11-17-lightsaml-signature-bypass-ghsa-w553-pwx6-3mg9
event_id: brief-2026-11-17-lightsaml-signature-bypass-ghsa-w553-pwx6-3mg9
revision: 1
activity_at: "2026-11-17T03:32:59Z"
title: 'LightSAML: Signature wrapping authentication bypass (CVE-2026-63182)'
slug: 2026-11-lightsaml-signature-bypass-ghsa-w553-pwx6-3mg9
description: LightSAML and its dependency xmlseclibs contain a signature validation discrepancy that allows an attacker to perform an XML Signature Wrapping (XSW) attack to bypass authentication or escalate privileges.
date: "2026-11-17T03:32:59Z"
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
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:lightsaml:lightsaml:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - xml-signature-wrapping
  - cve-2026-63182
vendors:
  - LightSAML
products:
  - LightSAML
product_versions:
  - product: LightSAML
    range: < 4.7.1
  - product: LightSAML
    range: '>= 5.0.0, < 5.0.1'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can craft a SAML response containing a genuine signed assertion... allowing attackers to authenticate as arbitrary users or escalate privileges.
cves:
  - id: CVE-2026-63182
    cvss: 8.1
    epss: 0.00191
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-w553-pwx6-3mg9
  - https://cveawg.mitre.org/api/cve/CVE-2026-63182
action_plan:
  priority: immediate_escalation
  immediate_actions:
    - action: Upgrade composer/litesaml/lightsaml to version 4.7.1 or 5.0.1
      due: ASAP
  hunt_leads:
    - lead: Identify SAML authentication logs where assertion validation occurs, specifically looking for abnormal or multiple assertion IDs within a single response structure
      data_needed:
        - webserver_logs
        - application_audit_logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability involves presenting multiple saml:Assertion elements, one genuine and one forged, within a single samlp:Response.
---

## Overview

LightSAML versions prior to 4.7.1 and 5.0.1 are vulnerable to an XML Signature Wrapping (XSW) attack. The vulnerability arises because LightSAML and the underlying library `robrichards/xmlseclibs` disagree on which assertion within a SAML response is covered by a signature. LightSAML collects direct-child assertions for processing, while `xmlseclibs` uses a document-wide XPath (`//*[@Id]`) to resolve the signed reference. This discrepancy enables an attacker to provide a genuine signed assertion (stripped of its signature) in the `samlp:Extensions` element and a forged, unsigned assertion in the expected position, causing the validator to verify the genuine assertion while the application processes the attacker-controlled claims.

## Attack Chain

1. Attacker captures a genuine, signed SAML response from a previous authentication session.
2. Attacker modifies the captured SAML response, removing the `ds:Signature` element from the original assertion.
3. Attacker embeds the signature-stripped original assertion into the `samlp:Extensions` block of the forged response, ensuring it remains the first ID-bearing element in the XML document.
4. Attacker constructs a forged `saml:Assertion` element as a direct child of the `samlp:Response`, containing malicious claims (e.g., elevated roles) and a copy of the genuine `ds:Signature`.
5. The vulnerable application receives the tampered response and triggers `AssertionSignatureValidatorAction`.
6. `xmlseclibs` performs signature verification, finds the genuine assertion in `samlp:Extensions` (via XPath document lookup), and successfully validates the cryptographic signature.
7. The application consumes the forged assertion's contents (NameID, Attributes) from the direct-child node, resulting in successful authentication bypass or privilege escalation.

## Impact

Successful exploitation allows an attacker to bypass SAML-based authentication mechanisms or escalate privileges, even when signature validation is explicitly required. The attacker can force the application to treat arbitrary, unsigned claims as valid and trusted identity attributes.

## Recommendation

- Immediately upgrade `litesaml/lightsaml` to version 4.7.1 or 5.0.1 to incorporate the patch addressing the signature validation logic.
- Inventory all applications utilizing `litesaml/lightsaml` for SAML 2.0 integration to prioritize deployment of the patched versions.
- Implement strict SAML assertion validation logic that explicitly verifies that the element identified by the XML signature's reference URI is identical to the assertion being processed by the application business logic.
