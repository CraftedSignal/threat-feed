---
brief_id: brief-2026-11-16-cursor-supply-chain
event_id: brief-2026-11-16-cursor-supply-chain
revision: 1
activity_at: "2026-11-16T17:10:51Z"
title: 'Cursor: Supply chain compromise via Fireworks AI breach'
slug: 2026-11-cursor-supply-chain
description: Attackers leveraged a compromised access key from Fireworks AI to gain unauthorized access to Cursor internal systems and inject malicious copies of the Anthropic Claude Code extension into the Cursor VS Code marketplace cache.
date: "2026-11-16T17:10:51Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.securityweek.com/cursor-supply-chain-attack-started-at-fireworks/
  observed_at: "2026-11-16T17:10:51Z"
  confidence: medium
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: likely
vendors:
  - Cursor
  - Fireworks AI
products:
  - anthropic.claude-code extension (versions 2.1.312 and 2.1.313)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
    evidence: A Cursor access key issued to Fireworks was compromised in one of these incidents and the attacker used it to copy data from a read-only storage bucket
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: the attacker used it to copy data from a read-only storage bucket, including unredacted credentials that opened the door to SaaS tools used by Cursor
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1195
    technique_name: Supply Chain Compromise
    subtechnique_id: T1195.002
    subtechnique_name: Compromise Software Supply Chain
    evidence: the attacker used secrets exfiltrated from the company’s internal systems to place “malicious, unauthorized copies of Anthropic's Claude Code extension directly on the cache used to serve the Cursor VS Code extension marketplace.”
references:
  - https://www.securityweek.com/cursor-supply-chain-attack-started-at-fireworks/
action_plan:
  hunt_leads:
    - lead: Monitor authentication logs for API keys or service tokens associated with third-party partners/vendors that are accessed from anomalous IP addresses or used to perform unusual cross-bucket read operations.
      technique_id: T1199
      data_needed:
        - Cloud provider API access logs
        - Identity and Access Management (IAM) audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: A Cursor access key issued to Fireworks was compromised in one of these incidents and the attacker used it to copy data from a read-only storage bucket.
    - lead: Search for scripts or automated processes searching for common credential file paths (e.g., .env, config.json, ssh keys) within non-production or archived source code repositories.
      technique_id: T1552
      data_needed:
        - Endpoint detection and response (EDR) process execution logs
        - Data Loss Prevention (DLP) logs for file scanning activity
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The attacker used it to copy data from a read-only storage bucket, including unredacted credentials that opened the door to SaaS tools used by Cursor.
    - lead: Baseline and monitor integrity of artifact caching servers or update distribution points; alert on unauthorized modifications or the replacement of signed binaries/extensions with unsigned or differently-signed versions.
      technique_id: T1195
      data_needed:
        - File integrity monitoring (FIM) logs
        - Content Delivery Network (CDN) / Cache server access logs
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: The attacker used secrets exfiltrated from the company’s internal systems to place “malicious, unauthorized copies of Anthropic's Claude Code extension directly on the cache used to serve the Cursor VS Code extension marketplace.”
---

## Overview
In October 2026, the AI inference platform Fireworks AI experienced two security incidents. The first involved the theft of internal credentials, and the second involved unauthorized access to development machines via a third-party cloud provider. During these incidents, a Cursor access key held by Fireworks was compromised.

## Attack Chain
Using the compromised access key, attackers accessed Cursor's internal systems, including non-production source code repositories, customer support data, and credentials. Following this, the attackers used exfiltrated secrets to place unauthorized, malicious copies of the 'anthropic.claude-code' extension (specifically versions 2.1.312 and 2.1.313) into the cache used to serve the Cursor VS Code extension marketplace. These malicious versions were served to users for approximately 11 hours. Cursor discovered the activity on October 29 and blocked the attacker's access.

## Impact
Cursor estimates that at most 5,000 users were affected by the malicious extension copies. Accessed data included non-production source code, customer support emails and conversations, product usage metrics, and user credentials submitted to the Cursor support team.

## Recommendation
Cursor considers the incident contained as of November 1. Users who installed or updated to 'anthropic.claude-code' versions 2.1.312 or 2.1.313 should follow the remediation steps provided in the official Cursor security notice, as simple uninstallation may be insufficient.
