---
brief_id: brief-2026-11-04-github-enterprise-updates
event_id: brief-2026-11-04-github-enterprise-updates
revision: 1
activity_at: "2026-11-04T21:09:06Z"
title: GitHub Enterprise Server Security Updates
slug: 2026-11-github-enterprise-updates
description: GitHub has released security updates for multiple versions of GitHub Enterprise Server to address undisclosed vulnerabilities.
date: "2026-11-04T21:09:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - vulnerability
  - enterprise-server
  - security-update
vendors:
  - GitHub
products:
  - Enterprise Server (3.19.0 < 3.19.14)
  - Enterprise Server (3.20.0 < 3.20.10)
  - Enterprise Server (3.21.0 < 3.21.8)
  - Enterprise Server (3.22.0 < 3.22.3)
references:
  - https://cyber.gc.ca/en/alerts-advisories/github-security-advisory-av26-1126
  - https://docs.github.com/en/enterprise-server@3.19/admin/release-notes
  - https://docs.github.com/en/enterprise-server@3.20/admin/release-notes
  - https://docs.github.com/en/enterprise-server@3.21/admin/release-notes
  - https://docs.github.com/en/enterprise-server@3.22/admin/release-notes
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade GitHub Enterprise Server to at least versions 3.19.14, 3.20.10, 3.21.8, or 3.22.3.
      owner: IT Operations
      addresses: GitHub Enterprise Server security updates
      evidence: As of November 3, 2026, GitHub is affected by vulnerabilities in the following product.
---

The Canadian Centre for Cyber Security has issued an advisory regarding security updates for GitHub Enterprise Server. These updates address multiple vulnerabilities across versions 3.19, 3.20, 3.21, and 3.22. Specific vulnerability details (CVEs and impact) were not disclosed in the advisory. Users and administrators are encouraged to consult the official release notes and apply updates to the recommended versions.

## Recommendation

- Inventory all GitHub Enterprise Server instances to identify versions 3.19.0-3.19.13, 3.20.0-3.20.9, 3.21.0-3.21.7, and 3.22.0-3.22.2.
- Upgrade affected GitHub Enterprise Server instances to the following minimum versions: 3.19.14, 3.20.10, 3.21.8, or 3.22.3.
- Monitor the official GitHub Enterprise Server documentation for forthcoming vulnerability details.
