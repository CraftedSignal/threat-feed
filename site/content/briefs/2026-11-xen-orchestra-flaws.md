---
brief_id: brief-2026-11-11-xen-orchestra-flaws
event_id: brief-2026-11-11-xen-orchestra-flaws
revision: 1
activity_at: "2026-11-11T16:44:19Z"
title: Vates Xen Orchestra Authentication Bypass and Zero-Day Exploitation
slug: 2026-11-xen-orchestra-flaws
description: A threat actor is actively exploiting a critical authentication bypass in the Xen Orchestra REST API and a separate zero-day vulnerability to achieve root-level code execution on XCP-ng nodes.
date: "2026-11-11T16:44:19Z"
type: threat
types:
  - threat
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Requires environment-specific validation of WAF rules for REST API token filtering
vendors:
  - Vates
products:
  - Xen Orchestra (< 6.9.2, < 6.10.1)
  - Xen Orchestra Appliance
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A threat actor has been exploiting a critical-severity authentication bypass and a zero-day in Xen Orchestra, software maker Vates warns.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This opens a route that exposes reusable login token IDs, allowing unauthenticated attackers to bypass authentication and gain administrator privileges.
    confidence_band: high
references:
  - https://www.securityweek.com/critical-xen-orchestra-flaws-exploited-in-attacks/
iocs:
  - type: ip
    value: 91.211.251.112
ioc_counts:
  ip: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Xen Orchestra to stable version 6.9.2 or latest 6.10.1
      owner: IT Operations
      due: 24h
      evidence: The security defect impacts Xen Orchestra releases before 6.9.2 (stable) and 6.10.1 (latest)
    - action: Block 91.211.251.112 at the perimeter firewall
      owner: SOC
      due: immediate
      evidence: According to the company, the attacker initially operated from 91.211.251.112:8001
  hunt_leads:
    - lead: Search for unusual or administrative-level activity in Xen Orchestra access logs originating from Tor exit nodes
      data_needed:
        - Xen Orchestra application logs
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The attacker initially operated from 91.211.251.112:8001 and via the Tor network.
  mitigation_plan:
    - priority: immediate
      action: Apply WAF configuration to block empty tokens in REST API requests
      owner: IT Operations
      addresses: Authentication bypass vulnerability
      evidence: The company recommends... blocking the empty token in a WAF rule
---

Vates has issued a warning regarding active exploitation of two vulnerabilities in Xen Orchestra, a backup and management solution for XCP-ng and XenServer environments. The first is a critical authentication bypass in the REST API mechanism, triggered by an empty authentication token, which allows attackers to impersonate valid users and gain administrator privileges. The second is an unpatched zero-day vulnerability allowing malicious VM imports that result in host compromise. No CVE identifiers have been assigned to these flaws. 

## Attack Chain
1. Attacker establishes initial contact via 91.211.251.112:8001 or Tor network.
2. Attacker exploits an empty token vulnerability in the Xen Orchestra REST authentication mechanism to bypass authentication.
3. Attacker gains unauthorized administrator access to the Xen Orchestra interface.
4. Attacker leverages a zero-day vulnerability related to VM imports to gain access to XCP-ng hosts.
5. Attacker executes arbitrary code as root on the underlying virtualization host.
6. Attacker establishes persistent access or backdoors on the compromised virtualization node.

## Impact
Confirmed compromise leads to full root-level takeover of XCP-ng virtualization nodes. Cleanup efforts are considered unreliable by the vendor, and a full reinstallation of affected nodes is recommended following a confirmed incident.

## Recommendation
- Upgrade Xen Orchestra to version 6.9.2 (stable) or 6.10.1 (latest) or higher immediately.
- Rotate all administrative and service credentials for the Xen Orchestra environment.
- Isolate Xen Orchestra instances behind a dedicated management network.
- Implement a WAF rule to block empty authentication tokens in REST API requests.
- Conduct a full reinstallation of systems where compromise is confirmed.
- Block communication with the observed malicious infrastructure (91.211.251.112).
