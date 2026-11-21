---
brief_id: brief-2026-11-18-agent-framework-pypi
event_id: brief-2026-11-18-agent-framework-pypi
revision: 2
activity_at: "2026-11-21T10:05:30Z"
revision_history:
  - revision: 2
    at: "2026-11-21T10:05:30Z"
    checksum: sha256:66a4e41eacb3a5b7537ae7b5cb11f14e6df2a404bec25bb9e509fd56980e8557
    summary: new IOCs
    changed_fields:
      - lastmod
      - references
      - updates
    source_urls:
      - https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html
title: 'Microsoft agent-framework: Credential stealer in PyPI package'
slug: 2026-11-agent-framework-pypi
description: Malicious versions 1.26.1 and 1.26.2 of the Microsoft agent-framework package were published to PyPI, containing a credential stealer.
date: "2026-11-18T02:57:41Z"
lastmod: "2026-11-21T10:05:09Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  likelihood: very likely
vendors:
  - Microsoft
products:
  - agent-framework
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    subtechnique_id: T1195.002
    subtechnique_name: Compromise Software Supply Chain
    evidence: On November 17, 2026 at 20:35 UTC, versions 1.26.1 & 1.26.2 of the Microsoft PyPI package agent-framework were published with an added credential stealer.
    confidence_band: high
references:
  - https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi
  - https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html
action_plan:
  hunt_leads:
    - lead: Identify systems that installed or updated to the malicious 'agent-framework' versions 1.26.1 or 1.26.2 between November 17, 2026, and the date of quarantine.
      technique_id: T1195
      data_needed:
        - Package manager logs (pip/conda)
        - Software Inventory/Asset Management logs
        - CI/CD build pipeline dependency logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: On November 17, 2026 at 20:35 UTC, versions 1.26.1 & 1.26.2 of the Microsoft PyPI package agent-framework were published with an added credential stealer.
updates:
  - at: "2026-11-21T10:05:09Z"
    level: L1
    summary: new IOCs
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html
---

## Overview
On November 17, 2026, at 20:35 UTC, versions 1.26.1 and 1.26.2 of the Microsoft PyPI package agent-framework were published with an added credential stealer. The package receives nearly 200,000 downloads monthly. The malicious versions have since been quarantined.

## Impact
Users who downloaded or installed the affected versions are potentially exposed to credential theft.

## Recommendation
Assess local environments for the presence of the identified malicious versions of the agent-framework package and ensure they have been removed.
