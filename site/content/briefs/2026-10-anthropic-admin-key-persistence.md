---
title: Anthropic Admin API Key Creation for Persistence
slug: 2026-10-anthropic-admin-key-persistence
description: Threat actors who compromise administrative accounts in the Anthropic platform can create durable Admin API keys to maintain long-term programmatic access that persists beyond interactive session revocation.
date: "2026-10-01T20:09:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - GenAI
  - Persistence
  - Identity-and-Access-Audit
vendors:
  - Anthropic
products:
  - Anthropic Console
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: An attacker who creates one after compromise can automate role grants, exports, and logging changes without holding a user session that would time out under SSO.
    confidence_band: high
references:
  - https://platform.claude.com/docs/en/api/compliance/activities/list
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/anthropic/persistence_anthropic_admin_api_key_created.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review existing Anthropic audit logs for any 'admin_api_key_created' activity.
      owner: SOC
      due: 24h
      evidence: Source provides explicit audit event action for monitoring.
  hunt_leads:
    - lead: Identify all active Admin API keys and verify them against known integration or authorized service accounts.
      technique_id: T1098.001
      data_needed:
        - Anthropic Audit Log API keys inventory
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Keys that cannot be mapped to authorized services are high-probability persistence tokens.
  mitigation_plan:
    - priority: immediate
      action: Revoke any unknown Admin API keys identified during the audit.
      owner: IT Operations
      addresses: Unauthorized API key persistence
      evidence: Source recommends revocation as the primary response to unauthorized creation.
---

This threat concerns the abuse of administrative credentials within the Anthropic platform. After successfully compromising an administrative account, threat actors may leverage their elevated permissions to generate new Admin API keys. Unlike standard interactive browser sessions protected by Single Sign-On (SSO), these API keys provide durable, programmatic access to sensitive organizational and compliance APIs. Because these keys do not time out, they allow an adversary to maintain presence and automate malicious activities - including exporting sensitive data, modifying roles, or suppressing compliance logs - even after the victim attempts to secure their account by resetting passwords or locking out the primary account from the Identity Provider (IdP). This technique represents a high-impact persistence mechanism that bypasses standard account lifecycle management controls.

## Attack Chain

1. Attacker gains unauthorized access to a privileged Anthropic user account (via credential harvesting or session hijacking).
2. Attacker logs into the Anthropic Console using the compromised credentials.
3. Attacker navigates to the API credential management section within the administrative dashboard.
4. Attacker creates a new Admin API key, assigning broad scopes to maximize control-plane access.
5. Attacker stores the newly generated key securely to ensure off-platform persistence.
6. Attacker leverages the API key to perform automated reconnaissance, data exfiltration, or modification of security settings.
7. Attacker uses the programmatic access to maintain activity even if the original compromised interactive account is disabled or revoked by defenders.

## Impact

Successful exploitation allows for long-term persistence within an organization's Anthropic instance. Attackers can bypass standard SSO session timeouts, maintain access following account recovery efforts, and automate large-scale data exports or modifications to sensitive compliance logs. This impacts the confidentiality, integrity, and availability of an organization's AI deployment and associated proprietary data.

## Recommendation

Prioritize monitoring of administrative API key lifecycle events to identify unauthorized persistence.

* Deploy detection rules to audit all `admin_api_key_created` events within the Anthropic Audit log stream.
* Establish a formal inventory of approved Admin API keys; cross-reference every new creation event against verified change requests or onboarding tickets.
* Investigate any key creation performed by accounts that recently underwent primary ownership or administrative role changes.
* Upon detecting an unauthorized key creation, immediate response must include revoking the compromised `anthropic.audit.admin_api_key_id`, rotating all administrative credentials, and auditing API activity associated with the revoked key.
