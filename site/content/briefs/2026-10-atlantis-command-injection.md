---
brief_id: brief-2026-10-27-atlantis-command-injection
event_id: brief-2026-10-27-atlantis-command-injection
revision: 1
activity_at: "2026-10-27T20:04:26Z"
title: 'Atlantis: Command injection via atlantis.yaml workspace parameter (CVE-2026-116676)'
slug: 2026-10-atlantis-command-injection
description: Atlantis versions 0.4.0 through 0.47.0 contain a command injection vulnerability where shell metacharacters in the workspace parameter can trigger arbitrary code execution as the service account.
date: "2026-10-27T20:04:26Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source supported; environment validation of the command injection path in Atlantis is required.
cpes:
  - cpe:2.3:a:runatlantis:atlantis:*:*:*:*:*:*:*:*
vendors:
  - Atlantis
products:
  - Atlantis (< 0.47.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: An authenticated contributor whose pull request is eligible for an Atlantis plan can include shell metacharacters in the workspace name, causing arbitrary commands to execute as the Atlantis service account.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: External contributors can reach the flaw through fork pull requests only when --allow-fork-prs is enabled, while eligible same-repository branches do not require that option.
    confidence_band: high
cves:
  - id: CVE-2026-116676
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116676
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Atlantis to 0.47.1
      owner: IT Operations
      due: 24h
      evidence: The issue is fixed in version 0.47.1.
  hunt_leads:
    - lead: Identify child processes spawned by the Atlantis service account that are not standard Terraform binaries
      technique_id: T1059.004
      data_needed:
        - Process creation logs (e.g., Sysmon Event ID 1 or Linux auditd)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Commands inherit the Atlantis process environment and can access cloud-provider, Terraform, and version-control credentials.
  mitigation_plan:
    - priority: immediate
      action: Disable --allow-fork-prs if not required
      owner: IT Operations
      addresses: CVE-2026-116676
      evidence: External contributors can reach the flaw through fork pull requests only when --allow-fork-prs is enabled.
---

Atlantis versions 0.4.0 through 0.47.0 are vulnerable to command injection through the workspace value defined in the atlantis.yaml configuration file. This vulnerability arises because the workspace parameter is improperly sanitized before being included in a Terraform command argument joined and executed via sh -c. An authenticated contributor can inject shell metacharacters into the workspace name to execute arbitrary commands with the privileges of the Atlantis service account. This allows for potential access to sensitive environment variables, cloud provider credentials, and Terraform state files. The issue is addressed in version 0.47.1.

## Impact

Successful exploitation allows for arbitrary command execution as the Atlantis service user. This provides access to the process environment, including cloud-provider and version-control credentials, Terraform state files, and internal network resources reachable from the host.

## Recommendation

- Upgrade Atlantis to version 0.47.1 or later immediately.
- Audit atlantis.yaml configurations in existing repositories for suspicious or unconventional workspace names.
- Evaluate the risk of the --allow-fork-prs flag; disable this option if not strictly required to mitigate exposure to external contributors.
- Monitor the Atlantis service process for the execution of child processes that deviate from the expected Terraform workflow.
