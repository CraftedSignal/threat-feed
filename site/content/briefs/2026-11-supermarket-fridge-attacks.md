---
brief_id: brief-2026-11-03-supermarket-fridge-attacks
event_id: brief-2026-11-03-supermarket-fridge-attacks
revision: 2
activity_at: "2026-11-03T18:40:49Z"
revision_history:
  - revision: 2
    at: "2026-11-03T18:40:49Z"
    checksum: sha256:ceaf5528e415c84d13fac2dcb67f77b7a215eac5e1d0fae3ec0608c6301d83d5
    summary: added coverage for XWEB supervisory controllers (<= 1.12.1)
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - references
      - tags
      - updates
    source_urls:
      - https://therecord.media/british-businesses-caught-in-europe-wide-supermarket-fridge-attacks
title: Industrial Refrigeration Controller Unauthorized Access and Temperature Tampering
slug: 2026-11-supermarket-fridge-attacks
description: Attackers are exploiting internet-exposed industrial refrigeration controllers using factory-default credentials to force units into defrost mode, causing temperature spikes and food spoilage across European retail chains.
date: "2026-11-03T08:06:20Z"
lastmod: "2026-11-03T18:40:14Z"
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
  validation_status: Needs environment validation of existing external exposure.
tags:
  - industrial-control-systems
  - internet-exposed-device
  - authentication-bypass
  - supply-chain
  - vulnerability
vendors:
  - Danfoss
  - Copeland
  - Dixell
products:
  - AK-SM series controllers
  - AK-SC series controllers
  - XWEB systems
  - XWEB supervisory controllers (<= 1.12.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: every freezer hit on Monday had a management interface reachable from the internet.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Most of the login attempts relied on factory-default credentials that Danfoss documents publicly
    confidence_band: high
references:
  - https://www.securityweek.com/over-100-european-stores-hit-as-supermarket-fridge-attacks-resume/
  - https://therecord.media/british-businesses-caught-in-europe-wide-supermarket-fridge-attacks
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Identify all public-facing management interfaces for refrigeration hardware.
      owner: IT Operations
      due: 24h
      evidence: Exposed interfaces are the primary vector for unauthorized access.
    - action: Inventory and isolate all internet-facing Copeland XWEB controllers
      owner: IT Operations
      due: 24h
      evidence: Source states businesses were attacked through vulnerable internet-exposed controllers.
  hunt_leads:
    - lead: Identify unauthorized access attempts to refrigeration management interfaces from external IP addresses.
      technique_id: T1078
      data_needed:
        - Firewall/VPN logs showing access to industrial management ports (e.g., HTTP/HTTPS interfaces on specific vendor ports).
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Most login attempts relied on factory-default credentials.
    - lead: Search for unauthorized connections to XWEB controller management interfaces
      technique_id: T1190
      data_needed:
        - Firewall or proxy logs showing access to XWEB management ports
        - Web server access logs from the controller interface
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers identified via remote parameter changes during live sessions.
  mitigation_plan:
    - priority: immediate
      action: Isolate refrigeration controllers from the public internet and enforce MFA for remote access.
      owner: IT Operations
      addresses: Danfoss, Copeland, and Dixell controllers
      evidence: Danfoss recommended cutting internet connections and using secure networks only.
    - priority: immediate
      action: Upgrade Copeland XWEB firmware to version 1.12.2 or later
      owner: IT Operations
      addresses: Copeland XWEB (<= 1.12.1)
      evidence: Firmware update available since August 2026 to fix authentication bypass.
updates:
  - at: "2026-11-03T18:40:14Z"
    level: L1
    summary: added coverage for XWEB supervisory controllers (<= 1.12.1)
    sources:
      - therecord
    source_urls:
      - https://therecord.media/british-businesses-caught-in-europe-wide-supermarket-fridge-attacks
---

Multiple European supermarket chains in Belgium, Sweden, Ireland, the Netherlands, Finland, Italy, Portugal, and Estonia have reported targeted attacks on industrial refrigeration controllers. Attackers are gaining unauthorized access to internet-reachable management interfaces of Danfoss and Copeland/Dixell devices, forcing evaporators into defrost mode, which results in significant temperature increases and food loss. Experts confirm many targeted units are legacy, end-of-life devices lacking vendor patches. Initial findings indicate usage of publicly documented factory-default credentials to gain entry.

## Attack Chain
1. Reconnaissance: Attackers identify internet-exposed refrigeration management interfaces (e.g., Danfoss StoreView).
2. Initial Access: Attackers authenticate to the management interface using known factory-default credentials.
3. Execution: Attackers modify controller settings to force the refrigeration unit into an active defrost cycle.
4. Impact: The cooling mechanism is overridden, causing internal unit temperatures to rise (up to 50°C), resulting in spoiled food and potential fire hazards.

## Impact
Over 100 stores across Europe have been affected, including major retailers like Delhaize, Carrefour, and Spar. Reported impacts include massive food spoilage, financial losses for small and large grocers, and operational disruption to the regional food supply chain.

## Recommendation
- Identify and inventory all internet-facing refrigeration management systems (specifically Danfoss AK-SM, AK-SC series, and Copeland/Dixell XWEB systems).
- Immediately remove industrial refrigeration controllers from the public internet.
- Implement strict network segmentation and place controllers behind a secure VPN or firewall requiring multi-factor authentication for access.
- Audit all management interfaces for the use of default factory credentials and replace them with unique, strong passwords.
- For end-of-life units that cannot be patched, apply physical isolation or replace the controller with modern, supported hardware.
