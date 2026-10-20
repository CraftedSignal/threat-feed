---
brief_id: brief-2026-02-18-maltrail-iocs
event_id: brief-2026-02-18-maltrail-iocs
revision: 2
activity_at: "2026-02-18T23:44:32Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:0654dd33d7fb447dffe1f757b4156c65bcdaaed46f18e87958c131d605b6a4b1
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Maltrail Feed - Newly Observed Domains and IP Address
slug: 2026-02-18-maltrail-iocs
description: This brief details newly observed network activity, specifically a list of domains and one IP address, reported by the Maltrail feed on February 18, 2026, potentially indicating emerging threats or malicious infrastructure.
date: "2026-02-18T23:44:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
tags:
  - maltrail
  - network-ioc
  - domain
  - ip-address
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.circl.lu/doc/misp/feed-osint/09642568-6dd1-47f3-8064-7ef4e3b57fc4.json
iocs:
  - type: ip
    value: 212.111.89.17
  - type: domain
    value: 0bz6vz64.blue128cinder.digital
  - type: domain
    value: 0live-vvork.olive4parcel.coupons
  - type: domain
    value: 0ufhrxly.chattytolet.digital
  - type: domain
    value: 19z4t19x.matrimon63shadowy.digital
  - type: domain
    value: 33vq3044.agitate6vagina.digital
  - type: domain
    value: 3aofxgg5.orbit44kind.digital
  - type: domain
    value: 3k71xodj.serve5woodman.digital
  - type: domain
    value: 3uwms13u.ostroy56sagacious.digital
  - type: domain
    value: 5osnse1q.dozerebelt.digital
  - type: domain
    value: 5rfgvs2q.digimatrix.digital
  - type: domain
    value: 655rd9or.caretouched.digital
  - type: domain
    value: 65w6z13g.highlifeless.digital
  - type: domain
    value: 67ocfzzz.hangesulka.digital
  - type: domain
    value: 6qgqyv15.blue128cinder.digital
  - type: domain
    value: 7i84od4b.elastic-refurbish.digital
  - type: domain
    value: 7wgxbccc.cyberlane.digital
  - type: domain
    value: 7yj72fkc.mint2layer.digital
  - type: domain
    value: 8etmon1sto.ru
  - type: domain
    value: 8h6w2a84.matrimon63shadowy.digital
  - type: domain
    value: a5v9n.box3pear.coupons
  - type: domain
    value: a5v9n.capitul98hypo.coupons
  - type: domain
    value: a5v9n.grape1shipping.coupons
  - type: domain
    value: a6mm9t.glint39parko.coupons
  - type: domain
    value: a6t9q.whirl189wind.coupons
  - type: domain
    value: a7k3z.unt452hub.coupons
  - type: domain
    value: agitate6vagina.digital
  - type: domain
    value: agri-clock-core-sn.in.net
  - type: domain
    value: ai-api-cloud-program.in.net
  - type: domain
    value: altstadt.ja8u2rudila.ru
  - type: domain
    value: amber2vivid.coupons
  - type: domain
    value: amber9stash.coupons
  - type: domain
    value: anchor.pricepirate.coupons
  - type: domain
    value: ancienttree.coupons
  - type: domain
    value: api-cloud-dispatch-core.in.net
  - type: domain
    value: api-secure-mesh-cloud.in.net
  - type: domain
    value: api.dealharbor.coupons
  - type: domain
    value: api.nuitetoile.coupons
  - type: domain
    value: api.orbit6crate.coupons
  - type: domain
    value: app.perk9parcel.coupons
  - type: domain
    value: app.terrepure.coupons
  - type: domain
    value: app.vertjardin.coupons
  - type: domain
    value: app1e-vvex.apple2dispatch.coupons
  - type: domain
    value: apple2dispatch.coupons
  - type: domain
    value: archive.disapp43squithes.coupons
  - type: domain
    value: argentvif.8etmon1sto.ru
  - type: domain
    value: ark7r5k.kolos56tomat.coupons
  - type: domain
    value: arnb3r-0rb.amber2vivid.coupons
  - type: domain
    value: art67quarrel.coupons
  - type: domain
    value: artifact.homo483geneous.coupons
ioc_counts:
  domain: 49
  ip: 1
rules:
  - title: Detect Connections to Newly Observed Maltrail Domains
    description: Detects network connections to newly observed domains reported by the Maltrail feed.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1568.002
    data_sources:
      - network_connection
      - windows
  - title: Detect Outbound Connection to Maltrail IP Address
    description: Detects outbound network connections to the IP address 212.111.89.17 reported by Maltrail.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On February 18, 2026, the Maltrail feed reported a series of newly observed network indicators, primarily consisting of newly registered domains and a single IP address. These indicators may represent command-and-control infrastructure, phishing sites, or other malicious activities. The domains exhibit patterns suggestive of dynamically generated names, possibly to evade detection. While the exact nature of the threat is not explicitly defined in the report, the sudden appearance of these domains and the IP address warrants investigation to determine if they are associated with ongoing campaigns or emerging threats. This activity requires monitoring to assess its potential impact and prevent malicious activity.

## Attack Chain

Due to the limited information available from the Maltrail feed, the complete attack chain cannot be definitively established. However, based on the types of indicators observed, a hypothetical attack chain can be constructed:

1. **Initial Compromise (Possible):** A user may receive a phishing email or visit a compromised website.
2. **Redirection:** The user clicks a link that redirects to one of the newly observed domains.
3. **Malware Delivery (Possible):** The domain hosts malware or exploits a vulnerability on the user's system to install malware.
4. **Command and Control:** The malware communicates with the IP address `212.111.89.17` to receive instructions from the attacker.
5. **Lateral Movement (Possible):** The malware attempts to spread to other systems on the network.
6. **Data Exfiltration or Damage (Possible):** The malware exfiltrates sensitive data or causes damage to the compromised systems.

## Impact

The impact of these indicators is potentially broad, depending on the attacker's objectives. If these domains and the IP address are indeed associated with malicious activity, successful exploitation could lead to data theft, system compromise, and financial losses. The nature of the domain names suggests a possible phishing or malvertising campaign, targeting unsuspecting users. Without further analysis, it is difficult to determine the scale and scope of the potential impact.
