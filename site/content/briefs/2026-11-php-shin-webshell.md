---
brief_id: brief-2026-11-05-php-shin-webshell
event_id: brief-2026-11-05-php-shin-webshell
revision: 1
activity_at: "2026-11-05T13:32:57Z"
title: 'php.shin_webshell: Infrastructure updates and WordPress targeting'
slug: 2026-11-php-shin-webshell
description: ThreatFox has identified 25 new domains associated with the php.shin_webshell malware, which is utilized for payload delivery and targets WordPress administrative functions.
date: "2026-11-05T13:32:57Z"
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
qa_status:
  verdict: pass
tags:
  - webshell
  - php
  - wordpress
  - payload-delivery
vendors:
  - WordPress
products:
  - WordPress
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.003
    technique_name: Web Shell
    evidence: Indicators associated with php.shin_webshell malware targeting WordPress administrative functions.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/php.shin_webshell/
  - https://malpedia.caad.fkie.fraunhofer.de/details/php.shin_webshell
iocs:
  - type: domain
    value: hyxypini.workers.dev
  - type: domain
    value: crawl-144-217-135-156.dataproviderbot.com
  - type: domain
    value: 95.234.52.34.bc.googleusercontent.com
  - type: domain
    value: bawigelu.workers.dev
  - type: domain
    value: extra516.workers.dev
  - type: domain
    value: qj4pbwfysb-990.workers.dev
  - type: domain
    value: fno1lpv3m3.workers.dev
  - type: domain
    value: proxy-us-east007-cip5.ahrefs.net
  - type: domain
    value: 62helen.workers.dev
  - type: domain
    value: 43wylma.workers.dev
  - type: domain
    value: vps-a117b66a.vps.ovh.net
  - type: domain
    value: 208.56.156.34.bc.googleusercontent.com
  - type: domain
    value: qkff7oizsz.workers.dev
  - type: domain
    value: wadoho.workers.dev
  - type: domain
    value: verymiha.workers.dev
  - type: domain
    value: lujeviki.workers.dev
  - type: domain
    value: grubbymiguelita.workers.dev
  - type: domain
    value: vajyloco.workers.dev
  - type: domain
    value: nopesa.workers.dev
  - type: domain
    value: xbxza50287.workers.dev
  - type: domain
    value: ogtko71935.workers.dev
  - type: domain
    value: 6f35xsvz7x.workers.dev
  - type: domain
    value: kyqoryme.workers.dev
  - type: domain
    value: lbl11ijvqp.workers.dev
  - type: domain
    value: acwts46591.workers.dev
ioc_counts:
  domain: 25
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block the listed IOC domains in DNS and egress firewalls
      owner: SOC
      due: 24h
      evidence: ThreatFox list of active payload delivery domains
  hunt_leads:
    - lead: Hunt for outbound connections from web servers to the listed domains
      technique_id: T1505.003
      data_needed:
        - Proxy logs
        - DNS logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Domains identified as delivery infrastructure for webshells
---

Abuse.ch ThreatFox has documented 25 newly identified domains linked to the php.shin_webshell malware. These indicators, first reported on November 4, 2026, are primarily utilized for payload delivery and have been observed in contexts targeting WordPress installations and administrative panels.

## Impact

The identified indicators are used for payload delivery, indicating an ongoing campaign to deploy web shells on vulnerable WordPress environments to achieve persistence and unauthorized command execution.

## Recommendation

- Block all 25 identified domains at the organization's DNS resolver and perimeter firewall.
- Audit WordPress administrative access logs and file integrity monitoring (FIM) alerts for unexpected PHP file modifications, particularly those resembling web shell characteristics.
- Review WordPress plugin and theme installations for unauthorized additions.
