---
title: Agent Skill Marketplace Supply Chain Attack via GitHub Account Hijacking
slug: 2026-03-agent-skill-hijacking
description: A supply chain attack targets agent skill marketplaces by exploiting GitHub username hijacking, allowing threat actors to intercept skill downloads from vulnerable repositories, with scanners showing significant disagreement on malicious skill identification and embedded live API credentials discovered.
date: "2026-03-23T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - supply-chain
  - github
  - agent-skills
  - repository-hijacking
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://arxiv.org/abs/2603.16572
  - https://raxe.ai/labs/radar/radar-2026-002#malicious-or-not-adding-repository-context-to-agent-skill-classification
iocs:
  - type: url
    value: https://arxiv.org/abs/2603.16572
  - type: url
    value: https://raxe.ai/labs/radar/radar-2026-002#malicious-or-not-adding-repository-context-to-agent-skill-classification
ioc_counts:
  url: 2
rules:
  - title: Detect GitHub Username Registration
    description: Detects the creation of new GitHub user accounts, which could be an early indicator of username hijacking attempts.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1195
    data_sources:
      - web
      - github
  - title: Detect Download of Files from Recently Created GitHub Repository
    description: Detects downloads of files from GitHub repositories that have been created within a short timeframe, potentially indicating a recently hijacked repository.
    platform: sigma
    severity: medium
    tactics:
      - supply_chain
    techniques:
      - T1195
    data_sources:
      - web
      - github
rules_count: 2
---

A supply chain attack has been identified targeting agent skill marketplaces that utilize a link-out distribution model, specifically indexing skills via GitHub repository URLs. The vulnerability arises when original repository owners rename their GitHub accounts, making the previous username available for takeover. Attackers can claim the orphaned username, recreate the repository, and intercept all future skill downloads. A study found 121 skills forwarding to 7 vulnerable repositories, with the most-downloaded hijackable skill having over 2,000 downloads. Further analysis of 238,180 unique skills from various marketplaces revealed significant disagreement among scanners, with fail rates ranging from 3.79% to 41.93%. Additionally, live API credentials for services such as NVIDIA, ElevenLabs, Gemini, and MongoDB were found embedded within the analyzed corpus, highlighting a severe lack of security hygiene in the agent skill ecosystem. This attack highlights the risks associated with relying on external repositories and the need for robust validation mechanisms in agent skill marketplaces.

## Attack Chain

1. Original GitHub repository owner renames their account, making the old username available.
2. Attacker registers the now-available GitHub username.
3. Attacker recreates the repository at the same URL as the original skill.
4. Users download the "skill" from the marketplace, which now points to the attacker's repository.
5. The attacker's repository serves malicious code instead of the original skill.
6. The malicious code executes on the user's system or agent platform.
7. Attackers leverage the skill to gain access to the victim's environment.
8. Attackers exfiltrate sensitive data or deploy further malicious payloads.

## Impact

This supply chain attack can compromise systems and data by delivering malicious code through hijacked agent skills. The discovery of 121 vulnerable skills and 7 vulnerable repositories demonstrates the scale of this threat. The presence of live API credentials for major services like NVIDIA, ElevenLabs, Gemini, and MongoDB within the skill corpus suggests widespread insecure development practices. Successful exploitation can lead to data breaches, system compromise, and unauthorized access to cloud services, potentially impacting numerous users and organizations relying on these agent skills. The disagreement between scanners highlights the difficulty in detecting these malicious skills, further compounding the risk.

## Recommendation

*   Implement monitoring for GitHub repository ownership changes for all deployed skills to detect potential hijacking (refer to Attack Chain).
*   Pin skills to specific commit hashes rather than mutable branch heads to ensure code integrity (refer to Attack Chain).
*   Require a minimum of two independent scanners to flag a skill before treating it as confirmed malicious to reduce false positives (refer to Overview).
*   Deploy the Sigma rule below to identify potential GitHub username registration events (see "Detect GitHub Username Registration" rule).
*   Prefer direct-hosting marketplaces over link-out distribution models to reduce reliance on external repositories (refer to Overview).
