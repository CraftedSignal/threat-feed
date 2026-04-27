---
title: Agent Skill Marketplace Supply Chain Attack via GitHub Account Hijacking
slug: 2026-03-agent-skill-hijacking
description: A supply chain attack targets agent skill marketplaces by exploiting GitHub username hijacking, allowing threat actors to intercept skill downloads from vulnerable repositories, with scanners showing significant disagreement on malicious skill identification and embedded live API credentials discovered.
date: "2026-03-23T12:00:00Z"
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

A supply chain attack has been identified targeting agent skill marketplaces that utilize a link-out distribution model, specifically indexing skills via GitHub repository URLs. The vulnerability arises when original repository owners rename their GitHub accounts, making the previous username available for takeover. Attackers can claim the orphaned username, recreate the repository, and intercept all future skill downloads. A study found 121 skills forwarding to 7 vulnerable repositories, with…
