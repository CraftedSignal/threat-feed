---
brief_id: brief-2026-11-03-x-cpe-botnet
event_id: brief-2026-11-03-x-cpe-botnet
revision: 1
activity_at: "2026-11-03T18:17:29Z"
title: Videostrong Technology x.cpe Botnet
slug: 2026-11-x-cpe-botnet
description: The x.cpe botnet, operated by Videostrong Technology, utilized a pre-installed backdoor on over 1.3 million Android TV devices to deploy modular malware, disable security protections, and conduct unauthorized proxying, ad fraud, and network reconnaissance.
date: "2026-11-03T18:17:29Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Videostrong Technology
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: almost certain
qa_status:
  verdict: pass
  validation_status: Verified against source text
tags:
  - botnet
  - android
  - supply-chain
vendors:
  - Videostrong Technology
products:
  - Android TV boxes (including MECOOL brand)
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Compromise Software Supply Chain
    subtechnique_name: Compromise Software Dependencies
    evidence: Manufacturers must have their devices certified if they want access to Google apps and branding... Videostrong's compromised boxes, mostly sold under the MECOOL brand, evaded detection by using a backdoor to remotely install the malware after the devices were set up and online.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: Disable or Modify Tools
    subtechnique_name: Disable or Modify Tools
    evidence: It also disabled Play Protect, which would have otherwise flagged the silently installed packages as malicious.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    subtechnique_name: Web Protocols
    evidence: After devices appeared online, a stub application called x.cpe or com.oemservice would phone home.
    confidence_band: high
references:
  - https://arstechnica.com/google/2026/11/google-dismantles-botnet-secretly-running-on-1-3-million-android-tv-boxes/
  - https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet/
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit network logs for Android TV hardware communicating with unknown or suspicious domains, following identification of MECOOL devices.
      owner: SOC
      due: 24h
      evidence: Google says it has taken legal action to shut down the domains and servers Videostrong used to operate and install its malware.
  hunt_leads:
    - lead: Identify Android TV devices in the environment and baseline their network traffic for large volume proxy activity or unexpected connections to unknown C2 infrastructure.
      technique_id: T1071.001
      data_needed:
        - Firewall or proxy logs capturing traffic from Android TV IP addresses
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Google found most of the boxes were running residential proxies for routing large volumes of nefarious traffic.
  mitigation_plan:
    - priority: immediate
      action: Isolate MECOOL-branded and known Videostrong-manufactured Android TV boxes from the internal corporate network.
      owner: IT Operations
      addresses: Supply chain compromise via Videostrong hardware
      evidence: Google has cut ties with the company behind the botnet campaign.
---

Google’s Threat Intelligence Group identified and disrupted a large-scale botnet known as x.cpe, affecting more than 1.3 million Google-certified Android TV devices. The operation was attributed to Shenzhen-based manufacturer Videostrong Technology, which leveraged a pre-installed backdoor to remotely push malicious modules after device deployment. The malware transformed infected hardware into nodes for residential proxy networks, ad fraud schemes, and local network reconnaissance tools.

## Attack Chain

1. Supply Chain Compromise: Videostrong Technology pre-installs a stub application (com.oemservice) on Android TV hardware during manufacturing.
2. Initial Provisioning: The device is sold and set up by the end-user, connecting to the internet.
3. C2 Beaconing: The stub application initiates contact with attacker-controlled command-and-control servers.
4. Defense Evasion: The stub application disables Google Play Protect to prevent the detection of subsequent malicious payload installation.
5. Payload Deployment: The operator remotely installs modular malware payloads via system-level permissions granted to the stub application.
6. Malicious Execution: Modules execute unauthorized tasks including residential proxy traffic routing, ad fraud, and lateral network probing.

## Impact

Over 1.4 million devices were confirmed to be infected, with significant concentrations in Brazil, Malaysia, Iraq, Mexico, and Taiwan, and thousands of affected devices across the US, UK, Germany, Australia, and Canada. The botnet allowed operators to capture device screens, execute terminal commands, and probe local network infrastructure.

## Recommendation

* Inventory all Android TV devices within the corporate network, specifically identifying MECOOL-branded and white-label hardware manufactured by Videostrong Technology.
* Monitor network traffic for anomalies originating from Android TV devices, particularly high volumes of outbound traffic characteristic of residential proxy activity.
* Restrict internal network access for IoT and media streaming devices by isolating them in a dedicated VLAN with strictly enforced egress filtering.
* Implement device management policies that prohibit the use of unmanaged, consumer-grade Android TV hardware for accessing sensitive corporate resources.
