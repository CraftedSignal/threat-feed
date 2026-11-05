---
brief_id: brief-2026-11-05-strelastealer-indicators
event_id: brief-2026-11-05-strelastealer-indicators
revision: 1
activity_at: "2026-11-05T13:42:28Z"
title: 'StrelaStealer: New malicious infrastructure for payload delivery'
slug: 2026-11-strelastealer-indicators
description: Multiple domains and URLs have been identified as active delivery infrastructure for the StrelaStealer information stealer, frequently utilizing fake updates and malicious web redirects.
date: "2026-11-05T13:42:28Z"
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
  validation_status: Needs environment validation of IOCs
tags:
  - infostealer
  - malware
  - c2
  - networking
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: StrelaStealer is an information-stealing malware strain typically distributed via malicious web redirects and fake updates.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.strelastealer/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.strelastealer
iocs:
  - type: domain
    value: minchones.com
  - type: domain
    value: rabiajamil.com
  - type: domain
    value: kingdomcaster.com
  - type: domain
    value: kidsmoralstory.in
  - type: domain
    value: synnfjellporten.no.datasenter.no
  - type: domain
    value: www.kevinalton.com
  - type: domain
    value: www.arta-brasov.ro
  - type: domain
    value: cr1ymiykt1zwu345wf.pages.dev
  - type: url
    value: https://cr1ymiykt1zwu345wf.pages.dev/win/index.php?vq=WJp2R4rq8ulFJ6pLHdRutVREVDZ1aVVwa1AwM2ptd053aGpIZjZ4Y3ZVdjEveW9DcDBCejRKaW4wcEU5a1VVdlUwQTFVVmdxYlBjN21TSFBqZXpPVU8zbWtLcmdCMlVKdG9nOEJmWVp4TzI4T1F6empmdTI3dStTbHUxMmFQZHBLd2E5U2dLVkwzTGpFWTI2L1l4am9TQ0pqVnpFcm5qWURzUEZubDVMNzBMb05aQ1NZbHBNTnJYNlRjblgyTU9ValgrUkxvOHo4Q1JPQXczRg==
  - type: domain
    value: lamborshop.com
  - type: domain
    value: 12dim-xanth.xan.sch.gr
  - type: domain
    value: expovirtual2020.upsa.edu.bo
  - type: domain
    value: www.mwanainchi.co.ke
ioc_counts:
  domain: 12
  url: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block identified malicious domains and URLs at perimeter firewall and DNS resolvers
      owner: SOC
      due: 4h
      evidence: StrelaStealer infrastructure identified by ThreatFox
  hunt_leads:
    - lead: Identify outbound requests to domains in the IOC list using proxy/DNS logs
      technique_id: T1566
      data_needed:
        - Proxy/DNS logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Observed StrelaStealer infrastructure
    - lead: Hunt for HTTP GET requests containing unusually long base64-encoded query strings (vq parameter)
      technique_id: T1071
      data_needed:
        - Web proxy logs (full URL path and query)
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Observed StrelaStealer delivery URL pattern
---

ThreatFox has identified 13 new indicators of compromise (IOCs) associated with the StrelaStealer information-stealing malware. The indicators, observed on 2026-11-04, include domains and URLs primarily utilized for payload delivery. Observed patterns suggest these nodes participate in malicious web redirect chains, often involving the "fakeupdates" delivery mechanism.

## Recommendation

- Block the listed domains and URLs at the organization's DNS resolver and perimeter firewall.
- Implement outbound traffic monitoring for endpoints reaching out to untrusted or newly registered domains, particularly those serving PHP content over HTTP.
- Review proxy and web logs for requests containing long, base64-encoded query parameters similar to the identified URL pattern, as these may indicate staging or C2 communication.
