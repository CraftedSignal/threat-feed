---
brief_id: brief-2026-10-26-burrito-auth-bypass
event_id: brief-2026-10-26-burrito-auth-bypass
revision: 1
activity_at: "2026-10-26T19:44:55Z"
title: 'Burrito: Authentication bypass in webhook processing (CVE-2026-102649)'
slug: 2026-10-burrito-auth-bypass
description: Burrito Kubernetes operator prior to 0.13.0 fails to verify webhook signatures when the secret is empty, allowing attackers to forge repository events and trigger unauthorized terraform plan operations.
date: "2026-10-26T19:44:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified, requires environment configuration audit
cpes:
  - cpe:2.3:a:burrito:burrito:*:*:*:*:*:*:*:*
vendors:
  - Burrito
products:
  - Burrito (< 0.13.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Anyone who can reach burrito-server's endpoint and knows a tracked repository's URL can forge events to create or delete TerraformPullRequest custom resources.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Pairing a real, existing pull request number with an unrelated existing branch in the same repository can therefore cause an unauthorized terraform plan for affected layers.
    confidence_band: high
cves:
  - id: CVE-2026-102649
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102649
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Burrito to version 0.13.0 or later
      owner: IT Operations
      due: 24h
      evidence: This issue is fixed in version 0.13.0.
  hunt_leads:
    - lead: Identify TerraformRepository resources with missing or empty WebhookSecret
      technique_id: T1190
      data_needed:
        - Kubernetes resource configurations (TerraformRepository custom resources)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Credential.WebhookSecret is optional, and go-playground/webhooks skips signature or token verification when the secret is empty.
  mitigation_plan:
    - priority: immediate
      action: Configure non-empty WebhookSecret for all TerraformRepository objects
      owner: IT Operations
      addresses: CVE-2026-102649
      evidence: The underlying library skips signature verification when the secret is empty.
---

Burrito is a Terraform Automation Collaboration Software (TACoS) Kubernetes operator. Versions prior to 0.13.0 contain a vulnerability (CVE-2026-102649) where the `POST /api/webhook` endpoint fails to authenticate GitHub and GitLab events if a `TerraformRepository` has no `webhookSecret` defined. Because the secret is optional, the underlying library `go-playground/webhooks` skips verification, allowing unauthenticated attackers with network access to the `burrito-server` to submit forged webhook payloads.

## Impact
An attacker can create or delete `TerraformPullRequest` custom resources by injecting forged events. By pairing a valid pull request number with a controlled branch, an attacker can force the operator to execute a `terraform plan` using its stored Git and cloud credentials. While the vulnerability does not directly trigger a `terraform apply`, it facilitates unauthorized exposure of infrastructure changes and potential code execution during the plan phase if the attacker-controlled branch contains malicious provider or data-source configurations.

## Recommendation
- Upgrade Burrito to version 0.13.0 or later immediately.
- Audit all `TerraformRepository` configurations in your Kubernetes environment to ensure the `webhookSecret` field is configured and non-empty.
- Restrict network access to the `burrito-server` endpoint to only allow incoming traffic from legitimate GitHub or GitLab IP ranges.
