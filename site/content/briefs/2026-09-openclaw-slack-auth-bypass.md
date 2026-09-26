---
title: Authentication Bypass in OpenClaw Slack
slug: 2026-09-openclaw-slack-auth-bypass
description: OpenClaw Slack versions prior to 2026.8.1 fail to enforce sender allowlists in multi-person direct messages, allowing unauthorized participants to interact with Slack agents and access restricted tools or data.
date: "2026-09-26T04:57:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openclaw:slack:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - cloud
vendors:
  - OpenClaw
products:
  - Slack (< 2026.8.1)
cves:
  - id: CVE-2026-100575
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100575
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenClaw Slack to 2026.8.1 or later to address CVE-2026-100575
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-100575 advisory requirement
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenClaw Slack to 2026.8.1
      owner: IT Operations
      addresses: CVE-2026-100575
      evidence: NVD advisory
---

OpenClaw Slack versions prior to 2026.8.1 contain an authentication bypass vulnerability, tracked as CVE-2026-100575, within the application's multi-person direct messaging component. The flaw stems from a failure to correctly validate sender allowlists when participants interact with automated agents configured within the chat environment. By bypassing these sender policies, an unauthorized or disallowed participant in a multi-person conversation can trigger agent execution, effectively masquerading as authorized users. This allows attackers to invoke tools and access sensitive data granted to the agent service accounts, potentially leading to unauthorized data exfiltration or manipulation of connected third-party services. Given the reliance on agent-based workflows, this vulnerability presents a significant risk to organizations using OpenClaw Slack for internal automation.

## Impact

Successful exploitation of this vulnerability allows unauthorized users within a multi-person chat thread to perform actions on behalf of Slack agents. This can result in unauthorized access to internal tools, data retrieval, and the potential execution of malicious commands or queries through agent-integrated systems. The scope of impact is limited to the permissions granted to the specific Slack agent compromised by the bypass.

## Recommendation

1. Upgrade OpenClaw Slack installations to version 2026.8.1 or later immediately to resolve CVE-2026-100575.
2. Review and audit current Slack agent permissions to minimize the potential blast radius of unauthorized interactions.
3. Restrict sensitive agent integrations to dedicated channels where participant access can be strictly managed until the patch is deployed.
