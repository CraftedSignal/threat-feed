---
brief_id: brief-2026-11-05-openbmb-internet-of-agents-auth-bypass
event_id: brief-2026-11-05-openbmb-internet-of-agents-auth-bypass
revision: 1
activity_at: "2026-11-05T15:47:00Z"
title: 'OpenBMB Internet of Agents: Authentication Bypass (CVE-2026-123032)'
slug: 2026-11-openbmb-internet-of-agents-auth-bypass
description: An authentication bypass vulnerability in the OpenBMB Internet of Agents WebSocket Connection Manager allows unauthenticated remote attackers to gain unauthorized access via manipulation of the agent_name parameter.
date: "2026-11-05T15:47:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Ready for production deployment pending environment-specific log validation.
cpes:
  - cpe:2.3:a:openbmb:internet_of_agents:*:*:*:*:*:*:*:*
vendors:
  - OpenBMB
products:
  - Internet of Agents (<= 9d78e88e47160eb42ee1ee8538c05e1c2c47877a)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-123032
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123032
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Restrict external access to WebSocket endpoints used by Internet of Agents.
      owner: SOC
      due: 24h
      evidence: Vulnerability allows unauthenticated remote access to server functionality.
  hunt_leads:
    - lead: Identify connections to WebSocket endpoints featuring suspicious or null agent_name arguments.
      technique_id: T1595
      data_needed:
        - Web server access logs
        - WebSocket gateway logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Manipulation of the argument agent_name results in missing authentication.
---

CVE-2026-123032 describes an authentication bypass vulnerability within the ConnectionManager.connect function of the im_server/app.py file in the OpenBMB Internet of Agents WebSocket Connection Manager. An unauthenticated attacker can remotely manipulate the agent_name argument to circumvent authentication mechanisms. Public exploit code is available for this vulnerability. As the project uses a rolling release model, no specific version numbers are provided; all instances up to commit hash 9d78e88e47160eb42ee1ee8538c05e1c2c47877a are considered affected.

## Impact

The vulnerability allows unauthenticated remote attackers to establish connections to the server without proper authentication, potentially leading to unauthorized access to agent infrastructure or control functionality.

## Recommendation

- Monitor websocket connection logs for anomalous agent_name values or unexpected connection patterns from external, unauthenticated sources.
- Audit the project repository for updates or patches, as the maintainers have not yet responded to the reported vulnerability.
- Implement network-level restrictions or authentication proxies in front of the Internet of Agents server to limit exposure until a permanent patch is integrated into the rolling release.
