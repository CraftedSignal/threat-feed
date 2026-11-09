---
brief_id: brief-2026-11-09-iranian-irgc-cyber-ops
event_id: brief-2026-11-09-iranian-irgc-cyber-ops
revision: 1
activity_at: "2026-11-09T22:11:27Z"
title: IRGC-linked cyber operations against French industrial and public targets
slug: 2026-11-iranian-irgc-cyber-ops
description: The French C4 interministerial center has attributed multiple disruptive cyber operations against French national interests to Iranian IRGC-affiliated units Shahid Shoostari and Shahid Kaveh, including a recent large-scale attack against industrial refrigeration controllers.
date: "2026-11-09T22:11:27Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - IRGC
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
tags:
  - industrial-control-systems
  - nation-state-actor
  - sabotage
  - ics
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Les membres du Centre de Coordination des Crises Cyber (C4) ont observé plusieurs attaques à but de déstabilisation menées à l’encontre des intérêts français.
    confidence_band: high
references:
  - https://www.cert.cyber.gouv.fr/cti/CERTFR-2026-CTI-009/
  - https://www.diplomatie.gouv.fr/fr/presse-et-ressources/decouvrir-et-informer/actualites/declaration-d-attribution-a-l-iran-de-cyber-attaques-visant-la-france
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Perform network discovery to identify internet-exposed refrigeration controllers and ICS gateways
      owner: SOC
      due: 48h
      evidence: L’attaque ciblant des contrôleurs de réfrigération industriels français les 11 et 12 octobre 2026 constitue une attaque inédite
  hunt_leads:
    - lead: Identify unauthorized access attempts to industrial controllers and unusual outbound traffic from OT network segments
      technique_id: T1485
      data_needed:
        - Firewall logs
        - ICS/SCADA device access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: L’attaque ciblant des contrôleurs de réfrigération industriels français
  mitigation_plan:
    - priority: immediate
      action: Isolate all OT/ICS management interfaces from public-facing networks
      owner: IT Operations
      addresses: Industrial refrigeration controllers
      evidence: L’attaque ciblant des contrôleurs de réfrigération industriels français les 11 et 12 octobre 2026
  gaps:
    - Lack of specific technical indicators (IPs/hashes) prevents high-confidence automated detection
---

The French Centre de Coordination des Crises Cyber (C4), an interministerial body comprising ANSSI, COMCYBER, DGA, DGSE, and DGSI, has formally attributed a series of disruptive cyber operations to the IRGC-affiliated units "Shahid Shoostari" and "Shahid Kaveh." 

These operations, aimed at destabilization, date back to at least 2020. Notable incidents include targeting the Charlie Hebdo media outlet in 2023 and a French video display enterprise during the Paris 2024 Olympic and Paralympic Games. Most recently, on October 11 and 12, 2026, the units conducted an aggressive and unprecedented attack targeting industrial refrigeration controllers within France.

## Impact

Observed impact includes the disruption of industrial control systems, specifically refrigeration controllers, and previous historical disruption of public-facing media and event-related digital display infrastructure.

## Recommendation

1. Inventory and audit internet-exposed industrial control systems (ICS/SCADA), specifically refrigeration management controllers, to ensure they are not directly accessible from the public internet.
2. Implement strict network segmentation between IT and OT environments, applying the principle of least privilege to remote management interfaces.
3. Review and reinforce monitoring for anomalous traffic patterns directed toward industrial control hardware.
4. Integrate threat intelligence reporting from the ANSSI/CERT-FR bulletins into SOC threat hunting cycles to identify future activity associated with these IRGC units.
