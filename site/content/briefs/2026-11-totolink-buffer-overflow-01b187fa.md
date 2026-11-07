---
brief_id: brief-2026-11-07-totolink-buffer-overflow-01b187fa
event_id: brief-2026-11-07-totolink-buffer-overflow-01b187fa
revision: 1
activity_at: "2026-11-07T22:10:33Z"
title: 'TOTOLINK CA300-PoE: Remote buffer overflow in cstecgi.cgi (CVE-2026-124059)'
slug: 2026-11-totolink-buffer-overflow-01b187fa
description: TOTOLINK CA300-PoE version 6.2c.884 contains a remote buffer overflow vulnerability in the setWiFiWdsAddConfig function of /cgi-bin/cstecgi.cgi that allows authenticated attackers with high privileges to trigger memory corruption.
date: "2026-11-07T22:10:33Z"
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
  validation_status: Needs environment validation of specific device telemetry.
cpes:
  - cpe:2.3:a:totolink:ca300_poe:*:*:*:*:*:*:*:*
vendors:
  - TOTOLINK
products:
  - CA300-PoE (6.2c.884)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation of the argument ApCliKeyStr leads to buffer overflow.
    confidence_band: high
cves:
  - id: CVE-2026-124059
    cvss: 9.1
    kev_status: "false"
references:
  - https://vuldb.com/cve/CVE-2026-124059
  - https://sploitus.com/exploit?id=CVE-2026-124059
  - https://sploitus.com/exploit?id=CVE-2026-124059&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to the device web management interface to known internal administrative ranges.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability requires network access to the cgi script.
  hunt_leads:
    - lead: Identify unauthorized access to /cgi-bin/cstecgi.cgi on internal network devices.
      technique_id: T1190
      data_needed:
        - Web server access logs from network appliances
        - Firewall logs for internal administrative management traffic
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is exploited via /cgi-bin/cstecgi.cgi.
  mitigation_plan:
    - priority: immediate
      action: Apply firmware patches as provided by TOTOLINK when available.
      owner: IT Operations
      addresses: CVE-2026-124059
      evidence: Vulnerability impacts CA300-PoE 6.2c.884.
---

A remote buffer overflow vulnerability (CVE-2026-124059) exists in the TOTOLINK CA300-PoE firmware version 6.2c.884. The vulnerability is triggered via the setWiFiWdsAddConfig function within the /cgi-bin/cstecgi.cgi script. An attacker with high privileges can manipulate the ApCliKeyStr argument to induce a buffer overflow. Publicly available exploit code has been disclosed, increasing the risk of exploitation.

## Impact

Successful exploitation may result in memory corruption, potentially leading to unauthorized code execution or denial of service on the affected network device. The CVSS 4.0 score is 9.4, reflecting high impact on confidentiality, integrity, and availability.

## Recommendation

* Inventory all TOTOLINK CA300-PoE devices within the environment.
* Restrict administrative access to the device management interface (cstecgi.cgi) to trusted IP addresses or internal subnets only.
* Monitor for unauthorized administrative access or attempts to access /cgi-bin/cstecgi.cgi with unusual parameters.
* Disable unnecessary services, such as WDS (Wireless Distribution System) configurations, if not required for network operations.
* Consult the vendor for firmware updates addressing this vulnerability.
