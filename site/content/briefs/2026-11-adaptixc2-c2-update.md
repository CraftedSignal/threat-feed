---
brief_id: brief-2026-11-05-adaptixc2-c2-update
event_id: brief-2026-11-05-adaptixc2-c2-update
revision: 1
activity_at: "2026-11-05T13:34:02Z"
title: 'AdaptixC2: New botnet command-and-control infrastructure'
slug: 2026-11-adaptixc2-c2-update
description: ThreatFox identified a new AdaptixC2 botnet command-and-control server at 77.238.235.31:10443, indicating active network communication associated with this malware family.
date: "2026-11-05T13:34:02Z"
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
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: ThreatFox listed 1 new AdaptixC2 indicator of compromise (win.adaptix_c2) functioning as a botnet controller.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.adaptix_c2/
iocs:
  - type: ip
    value: 77.238.235.31
ioc_counts:
  ip: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block traffic to 77.238.235.31:10443 on firewall.
      owner: SOC
      due: 2h
      evidence: New AdaptixC2 indicator reported by abuse-ch.
  hunt_leads:
    - lead: Identify endpoints initiating network connections to 77.238.235.31.
      technique_id: T1071.001
      data_needed:
        - Firewall logs
        - Proxy logs
        - Sysmon Event ID 3
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: New AdaptixC2 C2 IP observed in active use.
---

ThreatFox has reported a new AdaptixC2 command-and-control (C2) node identified on 2026-11-04. The infrastructure facilitates botnet operations. As of this report, no specific exploit path or targeted product range is disclosed, but the threat is associated with the win.adaptix_c2 malware family.

## Recommendation

* Block all inbound and outbound traffic to the IP address 77.238.235.31 on port 10443 at the network perimeter.
* Hunt for internal network connections to the identified IP across firewall and proxy logs.
* Monitor host-based process telemetry for unexpected connections to external IPs using non-standard ports or associated with unrecognized processes.
