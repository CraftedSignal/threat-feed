---
title: Authorization Bypass in Quivr Prompt Management
slug: 2026-08-quivr-auth-bypass
description: An authorization flaw in Quivr versions 0.0.322 and earlier allows authenticated users to modify or overwrite arbitrary prompts via unvalidated API endpoints.
date: "2026-08-28T21:38:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:quivr:quivr:*:*:*:*:*:*:*:*
vendors:
  - Quivr
products:
  - Quivr (<= 0.0.322)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: The ability to modify system prompts allows an attacker to maintain persistent control over AI behavior within the shared environment.
    confidence_band: med
cves:
  - id: CVE-2026-82280
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82280
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to prompt management API endpoints for non-admin users
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82280 necessitates limiting endpoint access to prevent unauthorized modifications.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Quivr to version > 0.0.322
      owner: IT Operations
      addresses: CVE-2026-82280
      evidence: Source documentation identifies versions through 0.0.322 as affected.
---

Quivr versions up to and including 0.0.322 contain a critical authorization vulnerability (CVE-2026-82280) within its prompt management endpoints. The application fails to perform adequate ownership validation when processing requests to modify prompts. This allows any authenticated user, including those with only read-only access to shared 'brains', to discover valid prompt identifiers and subsequently issue unauthorized requests to overwrite them. By successfully altering these system prompts, an attacker can modify the behavior of the AI model for all users who interact with the affected shared environment. This vulnerability poses a significant risk to the integrity of AI-driven workflows and could be leveraged to perform prompt injection at scale or disrupt service delivery across an entire organizational brain.

## Impact

Successful exploitation enables an attacker to manipulate AI model responses by overwriting system prompts, potentially affecting all users connected to a compromised shared brain. This can lead to unauthorized information disclosure, the injection of malicious instructions, and a complete loss of control over the AI-generated output for specific tasks within the Quivr platform.

## Recommendation

- Upgrade Quivr to a version beyond 0.0.322 as soon as a patch is available.
- Implement restrictive API gateway controls to audit access to prompt-related endpoints until the vulnerability is remediated.
- Audit logs for unauthorized POST, PUT, or PATCH requests directed at prompt modification endpoints by accounts with restricted or read-only privileges.
- Monitor for anomalous prompt identifier discovery patterns in web server logs originating from low-privilege service accounts.
