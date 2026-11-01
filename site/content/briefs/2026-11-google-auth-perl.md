---
brief_id: brief-2026-11-01-google-auth-perl
event_id: brief-2026-11-01-google-auth-perl
revision: 1
activity_at: "2026-11-01T18:56:21Z"
title: 'Google::Auth for Perl: SSRF and OAuth state validation vulnerabilities (CVE-2026-74759, CVE-2026-74760)'
slug: 2026-11-google-auth-perl
description: The Google::Auth Perl module is vulnerable to server-side request forgery (SSRF) via unvalidated AWS credential URLs (CVE-2026-74759) and an OAuth authorization bypass (CVE-2026-74760) due to missing state validation in the gcloud-auth login callback.
date: "2026-11-01T18:56:21Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment verification of library usage
tags:
  - vulnerability
  - perl
  - oauth
  - ssrf
products:
  - Google::Auth (0.11-0.12)
cves:
  - id: CVE-2026-74759
    kev_status: "false"
  - id: CVE-2026-74760
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/462
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify all perl environments utilizing the Google::Auth module
      owner: IT Operations
      due: 48h
      evidence: Vulnerability impacts Perl applications using this library.
  hunt_leads:
    - lead: Monitor for unauthorized outbound connections originating from application servers using Google::Auth
      data_needed:
        - Network firewall or proxy logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: CVE-2026-74759 provides an SSRF vector which may result in unusual outbound traffic.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Google::Auth to the latest secure version
      owner: IT Operations
      addresses: CVE-2026-74759, CVE-2026-74760
      evidence: Patch required for identified vulnerabilities.
---

Two vulnerabilities were disclosed in the Google::Auth Perl module. CVE-2026-74759 concerns an SSRF vulnerability occurring when the library processes unvalidated `credential_source` URLs while handling AWS external account credentials. CVE-2026-74760 involves an authentication bypass in the `gcloud-auth` login callback, which fails to verify OAuth state parameters, allowing an attacker to inject an authorization code from an unauthorized local process.

## Impact
CVE-2026-74759 may allow an attacker to force the application to make unauthorized requests to internal network resources. CVE-2026-74760 may lead to account takeover or unauthorized access to Google Cloud resources if an attacker successfully intercepts or injects a local authorization callback.

## Recommendation
* Update Google::Auth for Perl to a patched version that resolves these vulnerabilities.
* Audit applications using Google::Auth to identify usage of AWS external account credentials or local `gcloud-auth` login workflows.
* Restrict local network access for applications performing OAuth flows to prevent unauthorized local process interference.
