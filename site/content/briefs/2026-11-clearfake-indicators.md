---
brief_id: brief-2026-11-05-clearfake-indicators
event_id: brief-2026-11-05-clearfake-indicators
revision: 1
activity_at: "2026-11-05T13:29:56Z"
title: 'ClearFake: New infrastructure identified for macOS payload delivery'
slug: 2026-11-clearfake-indicators
description: ThreatFox identified 35 new domains used by the ClearFake campaign to deliver malicious payloads, with recent infrastructure specifically targeting macOS users.
date: "2026-11-05T13:29:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    subtechnique_id: T1204.002
    subtechnique_name: Malicious File
    evidence: ClearFake is a malware distribution campaign that utilizes compromised websites and EtherHiding techniques to facilitate drive-by downloads.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/js.clearfake/
  - https://malpedia.caad.fkie.fraunhofer.de/details/js.clearfake
iocs:
  - type: domain
    value: efev6d2j.bossbeyvip3.xyz
  - type: domain
    value: ttjs9qkl.bossbeymax.click
  - type: domain
    value: 5pbqe4a7.bossbeyteam.click
  - type: domain
    value: bossbeyteam.click
  - type: domain
    value: j1ll6l7c.marya.store
  - type: domain
    value: v9sro8y6.jumar.store
  - type: domain
    value: r2wh6zpg.bossbeystar.click
  - type: domain
    value: bossbeystar.click
  - type: domain
    value: thewestore.store
  - type: domain
    value: e5a1y56u.leyka.store
  - type: domain
    value: pnsjbb2f.idaf.store
  - type: domain
    value: i1l77lh7.bossbeyspot.click
  - type: domain
    value: bossbeyspot.click
  - type: domain
    value: 3dmedworld.com
  - type: domain
    value: s9g2z9wi.bossbeyspace.click
  - type: domain
    value: bossbeyspace.click
  - type: domain
    value: 61tbj2c7.levoya.store
  - type: domain
    value: www.amberbriefs.au
  - type: domain
    value: www.rentaride.top
  - type: domain
    value: a9y70wox.haysam.store
  - type: domain
    value: skiathos.gr
  - type: domain
    value: esyscozo.bossbeyservice.click
  - type: domain
    value: bossbeyservice.click
  - type: domain
    value: v8lvhz7y.lecar.store
  - type: domain
    value: it0sxerr.hasir.store
  - type: domain
    value: sla.lovestoblog.com
  - type: domain
    value: 15f54so2.bossbeyroyal.click
  - type: domain
    value: bossbeyroyal.click
  - type: domain
    value: www.firedoormaintenance.com.au
  - type: domain
    value: kancelarianovus.pl
  - type: domain
    value: f015oa9h.kunci.store
  - type: domain
    value: m1woevi7.haon.store
  - type: domain
    value: www.cameliaholdings.co.za
  - type: domain
    value: z4d0x58u.bossbeypro.click
  - type: domain
    value: bossbeypro.click
ioc_counts:
  domain: 35
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block the 35 identified domains in the perimeter DNS and web proxy.
      owner: SOC
      due: 4h
      evidence: New ClearFake infrastructure indicators from ThreatFox.
  hunt_leads:
    - lead: Hunt for suspicious browser process activity initiating downloads of DMG, PKG, or ISO files from untrusted domains.
      technique_id: T1204.002
      data_needed:
        - EDR FileEvent logs
        - Web proxy logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: ClearFake targets macOS with payload delivery.
---

ThreatFox documented 35 new domains associated with the ClearFake campaign, a malware distribution network known for utilizing compromised websites and EtherHiding techniques to facilitate drive-by downloads. The newly identified infrastructure shows a targeted focus on macOS-based payloads, evidenced by associated naming conventions and metadata in the threat intelligence reporting.

## Impact

ClearFake campaigns utilize social engineering, often manifesting as fraudulent update prompts, to trick users into downloading malicious binaries. Observed activity primarily concerns payload delivery via drive-by download or deceptive landing pages.

## Recommendation

* Block the identified domains at the organization's DNS resolver and web proxy.
* Monitor EDR telemetry for browser-initiated downloads of suspicious DMG or PKG files, particularly from the newly identified infrastructure.
* Review web proxy logs for user traffic directed to the listed ".xyz", ".click", and ".store" domains.
