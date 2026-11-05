---
brief_id: brief-2026-11-05-mattermost-vulnerabilities
event_id: brief-2026-11-05-mattermost-vulnerabilities
revision: 1
activity_at: "2026-11-05T12:51:38Z"
title: 'Mattermost Desktop, Server, and Plugins: Multiple Vulnerabilities'
slug: 2026-11-mattermost-vulnerabilities
description: The BSI has reported multiple vulnerabilities across Mattermost Desktop, Server, and Plugins that may allow an attacker to perform unspecified actions.
date: "2026-11-05T12:51:38Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
tags:
  - vulnerability
  - informational
vendors:
  - Mattermost
products:
  - Mattermost Desktop
  - Mattermost Server
  - Mattermost Plugins
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4358
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  immediate_actions:
    - action: Inventory Mattermost infrastructure and prepare for patch deployment once versions are released.
      owner: IT Operations
      due: 72h
      evidence: BSI security advisory WID-SEC-2026-4358
---

The German Federal Office for Information Security (BSI) has issued a security advisory regarding multiple unspecified vulnerabilities affecting Mattermost Desktop, Mattermost Server, and various Mattermost Plugins. Technical details regarding the nature of these vulnerabilities, the potential attack vectors, and the specific impact remain undisclosed at this time. Organizations using these products should monitor the official Mattermost security updates page for further information.

## Recommendation

* Inventory all internal deployments of Mattermost Server, Desktop applications, and installed plugins.
* Monitor the official Mattermost security release notes and the BSI WID portal for the publication of patched versions and CVE identifiers.
* Prioritize applying vendor-supplied updates as soon as they become available for the affected product suite.
