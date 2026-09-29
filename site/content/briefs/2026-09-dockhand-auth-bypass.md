---
title: CVE-2026-53988 - Dockhand Authentication Bypass and Arbitrary Redeployment
slug: 2026-09-dockhand-auth-bypass
description: Dockhand versions prior to 1.0.40 contain an authentication bypass in git webhook endpoints allowing unauthenticated attackers to force arbitrary stack redeployments, leading to denial of service or potential host compromise.
date: "2026-09-29T20:29:41Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:dockhand:dockhand:*:*:*:*:*:*:*:*
vendors:
  - Dockhand
products:
  - Dockhand (< 1.0.40)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595.002
    technique_name: Vulnerability Scanning
    evidence: Attacker performs reconnaissance to identify public-facing Dockhand instances and enumerates sequential stack IDs.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attacker exploits the null secret guard condition to bypass authentication and trigger git clone/docker compose operations.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attacker leverages malicious docker-compose.yml with privileged bind mounts for container escape and host compromise.
    confidence_band: high
cves:
  - id: CVE-2026-53988
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53988
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Dockhand to 1.0.40 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-53988 remediation requires updating to version 1.0.40
  mitigation_plan:
    - priority: immediate
      action: Apply IP allowlisting on webserver/load balancer for webhook endpoints
      owner: Network Security
      addresses: CVE-2026-53988
      evidence: Authentication bypass allows any remote attacker to trigger actions; restricting access mitigates this vector
---

Dockhand versions before 1.0.40 are affected by an authentication bypass vulnerability (CVE-2026-53988) residing in its git webhook endpoints. The vulnerability stems from a flawed guard condition where a null webhook secret is incorrectly processed. This allows remote, unauthenticated attackers to send specially crafted, unsigned webhook requests to the application. By enumerating sequential stack IDs, an attacker can trigger unauthorized git clone and docker compose operations. If an attacker has write access to the git repository tracked by the stack, they can inject a malicious docker-compose.yml file containing privileged bind mounts, facilitating container escape and full host compromise. This flaw poses a critical risk to organizations relying on Dockhand for automated container orchestration, as it enables both service disruption and complete infrastructure takeover.

## Attack Chain

1. Attacker performs reconnaissance to identify public-facing Dockhand instances.
2. Attacker enumerates sequential integer-based stack IDs associated with the target's git webhook endpoints.
3. Attacker constructs unsigned HTTP POST requests targeted at identified webhook endpoints.
4. Attacker exploits the null secret guard condition to bypass authentication checks.
5. Attacker triggers a forced 'git clone' and 'docker compose' deployment operation via the webhook.
6. Attacker modifies the tracked git repository to include a malicious docker-compose.yml file.
7. Attacker triggers the redeployment, causing the malicious compose file to be executed with host-level privileges via bind mounts.
8. Attacker achieves container escape and full host compromise.

## Impact

Successful exploitation leads to unauthorized infrastructure management. Attackers can trigger mass redeployments, causing denial of service. Furthermore, if the attacker can modify the repository linked to a stack, they can execute arbitrary code on the underlying host, resulting in container escape and total server compromise.

## Recommendation

* Upgrade Dockhand to version 1.0.40 or later immediately to address CVE-2026-53988.
* Restrict network access to Dockhand webhook endpoints, allowing only legitimate source IP ranges (such as those from GitLab or GitHub webhooks).
* Implement monitor-only logging for all POST requests directed at /webhooks/git/* endpoints to identify attempts at sequential ID enumeration.
* Audit all active git-tracked stacks in Dockhand to ensure that linked repositories are secured against unauthorized commit access.
