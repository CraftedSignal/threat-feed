---
title: Authorization Bypass in iFlytek astron-agent
slug: 2026-08-astron-agent-auth-bypass
description: iFlytek astron-agent versions through 1.1.1 contain an authorization bypass vulnerability in the copyFlow endpoint, allowing authenticated attackers to access, overwrite, or exfiltrate workflows across tenant boundaries.
date: "2026-08-29T17:41:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:iflytek:astron-agent:*:*:*:*:*:*:*:*
vendors:
  - iFlytek
products:
  - astron-agent (<= 1.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: iFlytek astron-agent through 1.1.1 contains an authorization bypass vulnerability in the copyFlow endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-82475
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82475
rules:
  - title: Detect CVE-2026-82475 Exploitation - Unauthorized copyFlow Access
    description: Detects potential exploitation attempts of CVE-2026-82475 by monitoring for high volumes of access to the copyFlow endpoint, which may indicate enumeration or unauthorized exfiltration of workflow definitions.
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade astron-agent to a version beyond 1.1.1 to address CVE-2026-82475
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-82475 indicates vulnerability in versions <= 1.1.1
  hunt_leads:
    - lead: Search web logs for high-frequency POST requests to the /copyFlow endpoint
      technique_id: T1190
      data_needed:
        - Web application request logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Authorization bypass allows enumeration of workflow identifiers
---

iFlytek astron-agent versions through 1.1.1 are susceptible to an authorization bypass vulnerability located within the copyFlow endpoint. The vulnerability stems from a failure to perform adequate ownership validation when processing requests to copy or manipulate workflow data. Because the application does not verify if the authenticated user has appropriate permissions for the requested workflow identifier, an attacker can enumerate valid workflow IDs and perform unauthorized actions. This flaw impacts multi-tenant environments by permitting attackers to overwrite the workflows of other tenants or exfiltrate private workflow definitions. Defenders should prioritize patching, as this vulnerability allows for data exfiltration and integrity compromise within the agent platform.

## Impact

The vulnerability poses a significant risk to the confidentiality and integrity of automated workflows managed within astron-agent. If exploited, an attacker can read sensitive workflow logic and configuration (exfiltration) or modify existing processes (integrity compromise), potentially leading to further unauthorized operations within the affected tenant environment. The scope of targeting includes any multi-tenant deployment where tenant isolation is expected but not enforced at the application layer.

## Recommendation

1. Patch all deployments of astron-agent to a version later than 1.1.1 immediately, as remediation for CVE-2026-82475 is required to enforce proper ownership checks.
2. Implement strict input validation and authorization logging at the API gateway layer to detect excessive attempts to access the /copyFlow endpoint from non-authorized user contexts.
3. Review access logs for the copyFlow endpoint to identify potential workflow enumeration activity, characterized by high-frequency requests targeting different workflow identifiers from a single user session.
