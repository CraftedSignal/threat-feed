---
title: Authorization Bypass in holaOS Channel Gateway
slug: 2026-10-holaos-auth-bypass
description: A missing authorization vulnerability in holaOS channel-gateway connectors (CVE-2026-110769) allows unauthorized messaging-platform users to trigger arbitrary agent tasks on the host system.
date: "2026-10-14T20:33:11Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:holaos:holaos:*:*:*:*:*:*:*:*
vendors:
  - holaOS
products:
  - holaOS (<= 2026.822.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers who can message the operator's Telegram, Slack, Discord, or other bot can have ChannelIngress.handle pass turns to the workspace agent.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: This enables remote attackers to trigger the execution of configured tools on the operator's machine via the workspace agent.
    confidence_band: med
cves:
  - id: CVE-2026-110769
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110769
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Review and explicitly define the 'allowFrom' configuration in holaOS to mitigate the insecure default state.
      owner: Security Engineering
      due: 24h
      evidence: Source states the vulnerability occurs when the default allowFrom list is empty.
  mitigation_plan:
    - priority: immediate
      action: Upgrade holaOS to a version exceeding 2026.822.1.
      owner: IT Operations
      addresses: CVE-2026-110769
      evidence: holaOS through 2026.822.1 contains a missing authorization vulnerability
---

holaOS versions through 2026.822.1 contain a significant authorization flaw within their channel-gateway connectors. The vulnerability arises because the #isAllowed function fails to enforce sender validation when the default 'allowFrom' configuration list is empty, defaulting to an insecure state that accepts all incoming messages. 

Defenders should note that this vulnerability allows any user capable of sending a message to the operator's integrated messaging platform (e.g., Telegram, Slack, or Discord) to interact with the ChannelIngress.handle component. By bypassing access controls, remote attackers can submit agent tasks that are processed by the workspace agent. This effectively enables unauthorized users to execute configured tools on the operator's machine, potentially leading to unauthorized data access or local command execution depending on the toolset available to the agent.

## Impact

Successful exploitation allows remote, unauthenticated attackers to execute agent tasks on host machines where holaOS is deployed. This impacts the integrity of automated workflows and the security of the host environment, specifically in environments relying on integration with third-party messaging bots.

## Recommendation

* Upgrade holaOS to a version beyond 2026.822.1 once a patch is available.
* Audit existing holaOS configurations to ensure the 'allowFrom' list is explicitly populated, preventing the insecure default behavior.
* Monitor ingress traffic to messaging bot integrations for unexpected or anomalous agent task submissions from unauthorized users.
