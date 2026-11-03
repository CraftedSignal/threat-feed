---
brief_id: brief-2026-11-03-octo-sts-disclosure
event_id: brief-2026-11-03-octo-sts-disclosure
revision: 1
activity_at: "2026-11-03T04:05:19Z"
title: 'Octo STS: Trust policy information disclosure (CVE-2026-105770)'
slug: 2026-11-octo-sts-disclosure
description: Octo STS versions prior to 0.11.2 contain an information disclosure vulnerability where sensitive trust policy details, including internal cloud account identifiers and repository references, are exposed via Exchange error messages to unauthorized OIDC token holders.
date: "2026-11-03T04:05:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Vulnerability details confirmed by vendor advisory.
cpes:
  - cpe:2.3:a:octo-sts:octo_sts:*:*:*:*:*:*:*:*
vendors:
  - Octo STS
products:
  - Octo STS (< 0.11.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: An attacker who holds any validly signed OIDC token... can read that policy matching rules... These rules often name internal repositories, branches, environments or cloud account identifiers.
    confidence_band: high
cves:
  - id: CVE-2026-105770
    cvss: 5.3
    kev_status: "false"
references:
  - https://github.com/octo-sts/app/releases/tag/v0.11.2
  - https://github.com/octo-sts/app/security/advisories/GHSA-h5p6-j8m9-xx4p
  - https://sploitus.com/exploit?id=CVE-2026-105770
  - https://sploitus.com/exploit?id=CVE-2026-105770&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Octo STS to 0.11.2 or later
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in 0.11.2.
  hunt_leads:
    - lead: Identify unauthorized access attempts to Exchange endpoints resulting in PermissionDenied errors
      technique_id: T1592
      data_needed:
        - Exchange service application logs
        - HTTP response codes (403 Permission Denied)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: PermissionDenied errors included the policy issuer, subject and audience values... which Exchange returned verbatim.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Octo STS to 0.11.2
      owner: IT Operations
      addresses: CVE-2026-105770
      evidence: This issue is fixed in 0.11.2.
---

Octo STS versions before 0.11.2 are susceptible to an information disclosure flaw (CVE-2026-105770). The application inappropriately includes sensitive trust policy configuration fields - such as issuer, subject, audience patterns, and claim patterns - within 'PermissionDenied' error messages returned by the Exchange service. An unauthorized user possessing any validly signed OIDC token, including GitHub Actions tokens from attacker-controlled repositories, can trigger these errors to reveal internal security configurations, potentially including references to private repositories, branch names, environment settings, or cloud account identifiers. The vulnerability does not allow for token minting or security policy bypass.

## Impact

Successful exploitation allows an attacker to enumerate internal security architecture, mapping internal repositories, cloud accounts, and environment naming conventions. This information can be utilized for reconnaissance in further attacks against the organization's infrastructure.

## Recommendation

- Upgrade Octo STS to version 0.11.2 or later immediately to address the error handling flaw.
- Review internal trust policy configurations for any sensitive secrets or overly descriptive naming conventions that might have been disclosed if this vulnerability was exploited prior to patching.
