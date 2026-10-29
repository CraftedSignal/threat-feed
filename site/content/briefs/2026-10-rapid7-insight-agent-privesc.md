---
brief_id: brief-2026-10-29-rapid7-insight-agent-privesc
event_id: brief-2026-10-29-rapid7-insight-agent-privesc
revision: 1
activity_at: "2026-10-29T17:51:00Z"
title: 'Rapid7 Insight Agent: Local privilege escalation (CVE-2026-115805)'
slug: 2026-10-rapid7-insight-agent-privesc
description: A vulnerability in the Rapid7 Insight Agent for Linux and macOS allows an authenticated local user to achieve privilege escalation by supplying a crafted filesystem path during inventory collection.
date: "2026-10-29T17:51:00Z"
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
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment verification of affected agent versions.
cpes:
  - cpe:2.3:a:rapid7:insight_agent:*:*:*:*:*:linux:*:*
  - cpe:2.3:a:rapid7:insight_agent:*:*:*:*:*:macos:*:*
tags:
  - privilege-escalation
  - vulnerability
  - endpoint-security
vendors:
  - Rapid7
products:
  - Insight Agent
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Improper handling of local filesystem paths in Rapid7 Insight Agent on Linux and macOS may allow authenticated local users to gain elevated privileges.
    confidence_band: high
cves:
  - id: CVE-2026-115805
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115805
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify all Linux and macOS hosts running Rapid7 Insight Agent.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects Rapid7 Insight Agent on Linux and macOS.
  hunt_leads:
    - lead: Monitor for unusual filesystem path structures or unexpected file access patterns by the Insight Agent process.
      technique_id: T1068
      data_needed:
        - Auditd/syslog or Endpoint detection telemetry tracking process-related file system interactions
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability relates to improper handling of local filesystem paths during inventory collection.
  mitigation_plan:
    - priority: immediate
      action: Apply security patches for the Insight Agent when released by Rapid7.
      owner: IT Operations
      addresses: CVE-2026-115805
      evidence: NVD advisory for CVE-2026-115805.
---

CVE-2026-115805 is a privilege escalation vulnerability in the Rapid7 Insight Agent on Linux and macOS. The vulnerability exists due to improper handling of local filesystem paths during the agent's inventory collection process. An authenticated local user can exploit this flaw by providing a crafted filesystem path that the agent processes with elevated privileges, resulting in unauthorized privilege escalation on the affected host.

## Impact

An authenticated local user can escalate privileges on the host system. This requires the attacker to have existing local access to the system and the ability to influence paths processed by the agent.

## Recommendation

1. Inventory all systems running the Rapid7 Insight Agent on Linux and macOS.
2. Monitor Rapid7 security bulletins for patch availability for CVE-2026-115805 and deploy immediately to affected agents.
3. Restrict local user permissions on systems where the Insight Agent is deployed to limit the ability to place or manipulate filesystem paths accessible to the agent process.
