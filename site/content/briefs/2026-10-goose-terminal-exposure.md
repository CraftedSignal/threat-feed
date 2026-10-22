---
brief_id: brief-2026-10-22-goose-terminal-exposure
event_id: brief-2026-10-22-goose-terminal-exposure
revision: 1
activity_at: "2026-10-22T14:16:31Z"
title: 'Goose: Sensitive information disclosure via terminal integration (CVE-2026-111079)'
slug: 2026-10-goose-terminal-exposure
description: Goose terminal integration transmits unredacted shell command history, including API tokens and passwords, to external LLM providers, leading to potential credential exposure.
date: "2026-10-22T14:16:31Z"
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
  validation_status: Needs assessment of Goose configuration in production environments.
cpes:
  - cpe:2.3:a:goose:goose:*:*:*:*:*:*:*:*
tags:
  - sensitive-data-exposure
  - information-disclosure
  - llm-security
vendors:
  - Goose
products:
  - Goose (all versions with terminal integration enabled)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: This can lead to sensitive information disclosure, exposing confidential credentials to external service providers and logs.
    confidence_band: high
cves:
  - id: CVE-2026-111079
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111079
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Disable terminal integration feature in Goose application configuration
      owner: IT Operations
      due: 24h
      evidence: Vulnerability results from terminal integration feature capturing and transmitting history.
  mitigation_plan:
    - priority: immediate
      action: Disable the Goose terminal integration feature until an official patch for CVE-2026-111079 is released.
      owner: IT Operations
      addresses: CVE-2026-111079
      evidence: Source states terminal integration feature captures and transmits command history.
---

A vulnerability exists in the Goose terminal integration feature where shell command history is captured and transmitted verbatim to configured Large Language Model (LLM) providers without sanitization. This flaw causes sensitive user input, such as environment variables, API tokens, and passwords entered directly into the terminal, to be sent to external service providers.

## Impact
Sensitive information exposure occurs when confidential credentials or secrets are inadvertently included in shell command history and subsequently forwarded to third-party LLM endpoints. This results in the loss of data confidentiality and potential compromise of services accessible via the leaked credentials.

## Recommendation
- Review the configuration of Goose and identify all users with terminal integration enabled.
- Disable the terminal integration feature in Goose until a security update is applied to prevent the automatic transmission of command history.
- Conduct an audit of logs from configured LLM service providers to determine if sensitive information has been ingested during the period the terminal integration was active.
- Implement a policy to avoid typing secrets or credentials directly into terminal sessions where Goose or similar telemetry-collecting agents are active.
