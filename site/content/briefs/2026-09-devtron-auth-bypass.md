---
title: Devtron Authorization Bypass in Webhook API
slug: 2026-09-devtron-auth-bypass
description: Devtron versions 2.2.0 and earlier contain an authorization flaw in the orchestrator webhook endpoint that allows authenticated users to retrieve plaintext super-admin API tokens.
date: "2026-09-01T01:01:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:devtron:devtron:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
  - credential-access
vendors:
  - Devtron
products:
  - Devtron (<= 2.2.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An authenticated attacker can exploit this flaw to retrieve super-admin JWT tokens by providing arbitrary project, environment, and application parameters.
    confidence_band: high
cves:
  - id: CVE-2026-82882
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82882
rules:
  - title: Detect Unauthorized Access to Devtron Webhook Token Endpoint
    description: Detects GET requests to the /orchestrator/api-token/webhook endpoint, which should be restricted to administrative roles.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all internal Devtron deployments
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability notice
  mitigation_plan:
    - priority: immediate
      action: Monitor access to the affected endpoint
      owner: SOC
      addresses: CVE-2026-82882
      evidence: Source reporting of authorization bypass
---

Devtron versions 2.2.0 and earlier are affected by an authorization bypass vulnerability (CVE-2026-82882) located in the orchestrator webhook API. The vulnerability specifically affects the GET /orchestrator/api-token/webhook endpoint, which fails to validate the authorization level of the requesting user. An authenticated attacker, regardless of their original privilege level, can provide arbitrary project, environment, and application parameters to the endpoint to successfully query for and retrieve super-admin JSON Web Tokens (JWT) in plaintext. Successful exploitation provides the attacker with full platform control, enabling persistent access, configuration modifications, or unauthorized deployments within the Devtron environment. This vulnerability is critical for organizations using Devtron to manage CI/CD pipelines, as it allows for trivial privilege escalation to the highest administrative tier.

## Impact

Successful exploitation of this vulnerability results in full administrative control over the Devtron platform. Attackers can leverage the stolen super-admin tokens to perform any action the platform supports, including modifying deployment pipelines, accessing sensitive secrets managed by the platform, and pivoting into the underlying Kubernetes infrastructure. This allows for extensive persistence, data exfiltration, and potential supply chain compromise of the integrated CI/CD processes.

## Recommendation

1. Upgrade all Devtron instances to a version later than 2.2.0 immediately once a vendor patch is made available.
2. Implement strict monitoring on access to the /orchestrator/api-token/webhook endpoint in API gateway or web server logs.
3. Rotate all administrative tokens if it is suspected that an unauthorized user has accessed the platform.
4. Perform an audit of audit logs to identify any anomalous access to the webhook API endpoint by non-administrative user accounts.
