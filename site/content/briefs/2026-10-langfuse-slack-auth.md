---
title: 'CVE-2026-24055: Unauthenticated OAuth Slack Integration Leak in Langfuse'
slug: 2026-10-langfuse-slack-auth
description: An improper access control vulnerability in Langfuse allows unauthenticated attackers to hijack Slack integrations and exfiltrate sensitive project prompt data via the /api/public/slack/install endpoint.
date: "2026-10-05T01:00:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:langfuse:langfuse:*:*:*:*:*:*:*:*
tags:
  - langfuse
  - cve-2026-24055
  - access-control
  - slack-oauth
  - data-exfiltration
vendors:
  - Langfuse
products:
  - Langfuse (3.89.0 - 3.146.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The /api/public/slack/install endpoint does not require authentication, allowing an attacker to bind their own Slack workspace.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592.002
    technique_name: 'Gather Victim Org Information: Software'
    evidence: Once bound, any automation triggered within the victim's project that sends notifications to Slack will inadvertently exfiltrate sensitive data.
    confidence_band: high
cves:
  - id: CVE-2026-24055
    cvss: 5.3
    epss: 0.00442
references:
  - https://github.com/langfuse/langfuse/security/advisories/GHSA-pvq7-vvfj-p98x
  - https://github.com/langfuse/langfuse/commit/3adc89e4d72729eabef55e46888b8ce80a7e3b0a
rules:
  - title: Detect CVE-2026-24055 Exploitation Attempt
    description: Detects unauthorized access attempts to the Slack installation API endpoint in Langfuse
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
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Langfuse to 3.147.0
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies 3.147.0 as the fixed version
    - action: Audit Slack integrations for unrecognized workspaces
      owner: SOC
      due: 24h
      evidence: Attack utilizes unauthorized workspace binding
  hunt_leads:
    - lead: Search web logs for unauthenticated GET /api/public/slack/install
      technique_id: T1190
      data_needed:
        - Web application access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows unauthenticated access to this specific endpoint
  mitigation_plan:
    - priority: immediate
      action: Upgrade Langfuse to version 3.147.0
      owner: IT Operations
      addresses: CVE-2026-24055
      evidence: GitHub advisory GHSA-pvq7-vvfj-p98x
---

CVE-2026-24055 is an improper access control vulnerability (CWE-284, CWE-862) affecting Langfuse versions 3.89.0 through 3.146.0. The vulnerability resides in the /api/public/slack/install endpoint, which fails to enforce authentication or authorization checks during the Slack OAuth installation flow. By providing a target's unique projectId as a query parameter, an unauthenticated attacker can bind their own malicious Slack workspace to a victim's project. Once bound, any automation triggered within the victim's project that sends notifications to Slack will inadvertently exfiltrate sensitive data, including prompt content, metadata, labels, and tags, directly to the attacker-controlled Slack workspace. This vulnerability presents a high risk for organizations using Langfuse for prompt management, as it facilitates silent exfiltration of proprietary LLM development data.

## Attack Chain

1. Attacker identifies a target organization's unique Langfuse projectId through reconnaissance or information leakage.
2. Attacker prepares a malicious Slack application configured with a callback URL pointing to the target Langfuse instance.
3. Attacker crafts an HTTP GET request to the vulnerable endpoint: /api/public/slack/install?projectId=&lt;victim-project-id>.
4. The Langfuse application processes the request without authentication, triggering an OAuth redirect to Slack's authorization portal.
5. Attacker authorizes the malicious Slack workspace within the OAuth flow, completing the binding process.
6. The target victim, unaware of the unauthorized integration, performs routine operations such as updating or creating prompts.
7. Langfuse automation triggers, sending sensitive prompt metadata and content to the attacker-controlled Slack workspace.
8. Attacker gains full visibility into the victim's prompt library and development lifecycle events.

## Impact

The successful exploitation of this vulnerability leads to the unauthorized exfiltration of sensitive AI development assets, including prompt templates, system instructions, and project metadata. Organizations utilizing Langfuse to manage LLM prompts are vulnerable to intellectual property theft. There is no requirement for user interaction or privilege acquisition to conduct this attack, making it highly impactful for publicly accessible or misconfigured Langfuse instances.

## Recommendation

Prioritize the upgrade of all Langfuse deployments to version 3.147.0 or later to patch the authentication bypass on the Slack installation endpoint. Monitor web server logs for suspicious access to the /api/public/slack/install endpoint, particularly those originating from unauthenticated sessions or requests with unusual project identifiers. Review current Slack integrations within Langfuse settings to identify any unauthorized or unknown workspaces linked to sensitive projects.
