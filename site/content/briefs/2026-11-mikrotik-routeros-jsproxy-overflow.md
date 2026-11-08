---
brief_id: brief-2026-11-08-mikrotik-routeros-jsproxy-overflow
event_id: brief-2026-11-08-mikrotik-routeros-jsproxy-overflow
revision: 1
activity_at: "2026-11-08T13:45:03Z"
title: MikroTik RouterOS WebFig jsproxy Denial of Service (CVE-2026-84411)
slug: 2026-11-mikrotik-routeros-jsproxy-overflow
description: A pre-auth integer underflow in the MikroTik RouterOS WebFig /jsproxy endpoint allows unauthenticated attackers to cause a denial-of-service by triggering a crash of the www process.
date: "2026-11-08T13:45:03Z"
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
cpes:
  - cpe:2.3:a:mikrotik:routeros:*:*:*:*:*:*:*:*
tags:
  - mikrotik
  - routeros
  - webfig
  - denial-of-service
  - vulnerability
vendors:
  - MikroTik
products:
  - RouterOS (< 7.23.6, 7.24.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.004
    subtechnique_name: Application or System Exploitation
    evidence: Pre-auth heap overflow in RouterOS WebFig jsproxy causes DoS.
    confidence_band: high
cves:
  - id: CVE-2026-84411
    cvss: 9.8
    epss: 0.00864
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84411
  - https://sploitus.com/exploit?id=KS:EXPLOITS-LINUX-HTTP-MIKROTIK_ROUTEROS_CVE_2026_84411_JSPROXY
  - https://sploitus.com/exploit?id=KS:EXPLOITS-LINUX-HTTP-MIKROTIK_ROUTEROS_CVE_2026_84411_JSPROXY&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Potential CVE-2026-84411 Exploitation Attempt
    description: Detects malformed HTTP POST requests to the /jsproxy endpoint where Content-Type is msg and the body length mismatch is characteristic of the integer underflow vulnerability.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch RouterOS on all internet-facing devices to 7.23.6 or 7.24.3.
      owner: IT Operations
      due: 24h
      evidence: Vulnerable versions identified as < 7.23.6, 7.24.3.
  hunt_leads:
    - lead: Identify repeated POST requests to /jsproxy followed by service outage patterns.
      technique_id: T1499.004
      data_needed:
        - Web server logs
        - Device uptime / process status logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Public exploit triggers DoS by killing the www process.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to management ports 80/443 for MikroTik devices.
      owner: IT Operations
      addresses: CVE-2026-84411
      evidence: Vulnerability is exploitable over the network.
---

CVE-2026-84411 is a pre-auth integer underflow vulnerability in the MikroTik RouterOS WebFig interface's /jsproxy endpoint. The flaw is triggered when a specially crafted HTTP POST request with a 'Content-Type: msg' header is followed by a 'Content-Length' header that is smaller than the actual request body. Publicly available exploit modules demonstrate that this vulnerability can be leveraged to conduct denial-of-service (DoS) attacks by terminating the www process. No public weaponized RCE exploit is currently available, but the availability of reliable crash-mode PoC code increases the risk of service disruption.

## Impact

The vulnerability results in a denial-of-service by crashing the web management service (www process) on affected MikroTik devices. This renders the WebFig interface unavailable until the service is manually recovered or the device is rebooted.

## Recommendation

- Upgrade RouterOS to version 7.23.6, 7.24.3, or later to address the vulnerable jsproxy handling.
- Restrict access to the WebFig interface (typically port 80/443) to trusted management subnets via IP firewall filter rules.
- Inventory all internet-exposed MikroTik routers and prioritize patching or isolating the management interface.
