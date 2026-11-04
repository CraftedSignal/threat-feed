---
brief_id: brief-2026-11-04-herowatch-mini-missing-auth
event_id: brief-2026-11-04-herowatch-mini-missing-auth
revision: 1
activity_at: "2026-11-04T10:41:56Z"
title: About Time Technologies Herowatch Mini Missing Authentication (CVE-2026-121816)
slug: 2026-11-herowatch-mini-missing-auth
description: The Herowatch Mini device contains a missing authentication vulnerability in its ADB service, allowing unauthenticated remote attackers to gain command execution via an ADB shell.
date: "2026-11-04T10:41:56Z"
lastmod: "2026-11-04T10:42:05Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against CVE-2026-121816 metadata.
cpes:
  - cpe:2.3:a:about_time_technologies:herowatch_mini:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - iot
  - remote-code-execution
vendors:
  - About Time Technologies
products:
  - Herowatch Mini
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated remote attackers can connect to the affected device's ADB service and obtain an ADB shell
    confidence_band: high
cves:
  - id: CVE-2026-121816
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-121818
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121816
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121818
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Restrict network access to TCP 5555 for all identified Herowatch Mini devices
      owner: Network Security
      due: 24h
      evidence: Unauthenticated remote attackers can connect to the affected device's ADB service
  hunt_leads:
    - lead: Detect unauthorized connection attempts to TCP port 5555
      technique_id: T1190
      data_needed:
        - Firewall or network ingress logs showing traffic to port 5555 from untrusted subnets
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unauthenticated remote attackers can connect to the affected device's ADB service
  mitigation_plan:
    - priority: immediate
      action: Disable external access to ADB service via firewall rules
      owner: Network Security
      addresses: CVE-2026-121816
      evidence: Missing authentication in ADB service
updates:
  - at: "2026-11-04T10:42:05Z"
    level: L2
    summary: added CVE-2026-121818
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-121818
---

About Time Technologies Herowatch Mini is susceptible to a missing authentication vulnerability (CVE-2026-121816). This flaw allows unauthenticated remote attackers to connect directly to the Android Debug Bridge (ADB) service exposed on the device. Successful exploitation grants an attacker an ADB shell, providing full unauthorized access to device resources and the ability to execute arbitrary commands.

## Impact
Unauthorized remote actors can obtain an ADB shell on the device, leading to full compromise of device resources and potential persistent command execution.

## Recommendation
- Identify all Herowatch Mini devices currently connected to the network.
- Implement network-level access controls (such as ACLs on firewalls or routers) to restrict access to the ADB service port (default TCP 5555) to trusted management IP addresses only.
- Contact the vendor for firmware update availability to address the missing authentication in the ADB service.
