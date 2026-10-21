---
brief_id: brief-2026-10-21-localai-ssrf
event_id: brief-2026-10-21-localai-ssrf
revision: 1
activity_at: "2026-10-21T19:57:50Z"
title: 'LocalAI: Server-side request forgery (CVE-2026-114493)'
slug: 2026-10-localai-ssrf
description: LocalAI versions 4.6.0 through 4.11.0 are vulnerable to server-side request forgery (SSRF) allowing attackers to exfiltrate internal metadata via malicious configuration URLs.
date: "2026-10-21T19:57:50Z"
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
  - cpe:2.3:a:localai:localai:4.6.0:*:*:*:*:*:*:*
  - cpe:2.3:a:localai:localai:4.11.0:*:*:*:*:*:*:*
tags:
  - ssrf
  - webserver
  - cloud
vendors:
  - LocalAI
products:
  - LocalAI (v4.6.0 - v4.11.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can submit a config URL through POST /models/apply that redirects to internal or cloud metadata addresses.
    confidence_band: high
cves:
  - id: CVE-2026-114493
    cvss: 8.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114493
rules:
  - title: Detect CVE-2026-114493 Exploitation - POST /models/apply
    description: Detects potential SSRF attempts against LocalAI by monitoring for POST requests to /models/apply that may involve external configuration URLs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch LocalAI to a version newer than 4.11.0
      owner: IT Operations
      due: 48h
      evidence: Source notes version range v4.6.0 through v4.11.0 as vulnerable
  mitigation_plan:
    - priority: immediate
      action: Apply egress network restrictions to the LocalAI host to prevent access to 169.254.169.254
      owner: IT Operations
      addresses: CVE-2026-114493
      evidence: SSRF vulnerability allows access to cloud metadata services
---

LocalAI versions 4.6.0 through 4.11.0 contain a server-side request forgery (SSRF) vulnerability in the core gallery component. The application fails to properly validate redirect targets when processing gallery configuration URLs, allowing an attacker to submit a URL via the /models/apply endpoint that redirects to internal or cloud provider metadata services. This enables the attacker to receive and view sensitive internal responses.

## Impact
Successful exploitation allows an unauthorized attacker to perform SSRF, potentially accessing sensitive cloud metadata services or internal network resources that are otherwise not exposed to the public internet.

## Recommendation
- Upgrade LocalAI to a version beyond 4.11.0 to address the insecure URL validation in core/gallery/gallery.go.
- Implement egress filtering on the host machine running LocalAI to block unauthorized access to cloud metadata IP addresses (e.g., 169.254.169.254) and internal network segments.
- Audit and restrict access to the /models/apply endpoint to trusted administrative accounts.
