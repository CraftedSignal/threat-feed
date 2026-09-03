---
title: Authorization Bypass in OpenChoreo API Endpoints
slug: 2026-09-openchoreo-auth-bypass
description: An authorization flaw in the OpenChoreo API server allows authenticated users with project-scoped grants to execute commands and access logs across different projects within the same namespace.
date: "2026-09-03T00:03:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openchoreo:openchoreo_api:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cloud-security
  - authorization-bypass
vendors:
  - OpenChoreo
products:
  - openchoreo-api (v1.2.0-m.1 - 1.2.2)
  - openchoreo-api (< 1.1.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated tenant holding a project-scoped component:exec grant on just one project can execute arbitrary commands inside the running pods of components owned by any other project.
    confidence_band: high
cves:
  - id: CVE-2026-73841
    cvss: 8.8
    epss: 0.00353
references:
  - https://github.com/advisories/GHSA-52gf-6rpq-fgmx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73841
  - https://github.com/openchoreo/openchoreo/security/advisories/GHSA-rh53-xvx2-j327
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Team
  immediate_actions:
    - action: Upgrade openchoreo-api to version 1.2.3 or 1.1.6
      owner: IT Operations
      due: 24h
      evidence: Patches fixed in 1.2.3 and 1.1.6
  mitigation_plan:
    - priority: immediate
      action: Restrict component:exec and wirelogs:view grants to trusted operators
      owner: Security Team
      addresses: CVE-2026-73841
      evidence: Recommended workaround in GHSA-52gf-6rpq-fgmx
---

OpenChoreo versions prior to 1.2.3 and 1.1.6 contain an authorization bypass vulnerability (CVE-2026-73841) within the `openchoreo-api` component's `exec` and `wirelogs` endpoints. The API server incorrectly trusts user-supplied project identifiers to authorize requests instead of validating the target component against its actual owning project recorded in the internal resource hierarchy. Because the authorization engine only verifies if the caller holds a project-scoped grant (such as `component:exec` or `wirelogs:view`), a malicious actor with legitimate access to a single project can perform unauthorized operations on components belonging to other projects within the same Kubernetes namespace. This flaw enables cross-project command execution and unauthorized access to sensitive workload logs, potentially exposing environment variables, credentials, and secrets.

## Attack Chain

1. Attacker gains access to a low-privileged account with a valid `component:exec` or `wirelogs:view` grant for a single project within an OpenChoreo-managed namespace.
2. Attacker identifies a high-value target component in a different project within the same namespace.
3. Attacker crafts an HTTP request to the `openchoreo-api` `exec` or `wirelogs` endpoint.
4. Attacker substitutes the project parameter in the request with the identifier of the victim's component project.
5. The API server processes the request, resolving the target component by name without verifying the ownership relationship.
6. The authorization engine validates the attacker's grant against the caller-supplied (spoofed) project ID.
7. The server grants the attacker access, permitting command execution or log retrieval from the target component pod.

## Impact

The vulnerability allows unauthorized users to achieve remote command execution or sensitive data exfiltration from workloads they do not own, provided the target is within the same namespace. Successful exploitation allows for the compromise of environment variables and Kubernetes Secrets associated with the targeted component, lateral movement within the cluster, and potential disruption of service integrity across different organizational teams sharing a namespace.

## Recommendation

Prioritized actions for security and infrastructure teams:

- Upgrade `openchoreo-api` to version 1.2.3 or 1.1.6 immediately to enforce correct project-based authorization (CVE-2026-73841).
- Audit existing `component:exec` and `wirelogs:view` grants to ensure they are restricted to trusted operators only.
- Segregate highly sensitive components into distinct Kubernetes namespaces to prevent cross-project access while the patch is being deployed.
- Review cluster-gateway configuration to ensure internal proxies enforce caller authorization, addressing the related security gaps noted in GHSA-rh53-xvx2-j327.
