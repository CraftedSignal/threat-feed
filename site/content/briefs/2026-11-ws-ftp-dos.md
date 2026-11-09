---
brief_id: brief-2026-11-09-ws-ftp-dos
event_id: brief-2026-11-09-ws-ftp-dos
revision: 1
activity_at: "2026-11-09T21:59:11Z"
title: 'Progress Software WS_FTP Server: Denial of service via insufficient resource limits (CVE-2026-115339)'
slug: 2026-11-ws-ftp-dos
description: An unauthenticated remote attacker can trigger a denial of service condition in Progress Software WS_FTP Server versions prior to 2025.0.5 by exploiting insufficient resource limits.
date: "2026-11-09T21:59:11Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Patch version confirmed from NVD documentation
cpes:
  - cpe:2.3:a:progress:ws_ftp_server:*:*:*:*:*:*:*:*
vendors:
  - Progress Software
products:
  - WS_FTP Server (< 2025.0.5)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Insufficient resource limits in Progress Software WS_FTP Server releases prior to 2025.0.5 on Windows could allow an unauthenticated remote attacker to cause denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-115339
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115339
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Progress Software WS_FTP Server to version 2025.0.5 or later
      owner: IT Operations
      due: 48h
      evidence: NVD advisory specifies version 2025.0.5 as the fix
  hunt_leads:
    - lead: Identify sudden service instability or crashes in WS_FTP Server
      technique_id: T1499
      data_needed:
        - Windows System Event Logs (Service Control Manager)
        - WS_FTP Application Logs
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: Vulnerability allows remote attacker to cause denial of service
  mitigation_plan:
    - priority: immediate
      action: Restrict access to WS_FTP Server to known, trusted IP addresses
      owner: SOC
      addresses: CVE-2026-115339
      evidence: Mitigation of unauthenticated remote access until patch is applied
---

Progress Software WS_FTP Server versions prior to 2025.0.5 contain a vulnerability regarding insufficient resource limits. This flaw allows an unauthenticated remote attacker to cause a denial of service (DoS) on affected Windows-based systems. As of this report, the specific mechanics of the resource exhaustion (e.g., connection flooding or memory exhaustion) have not been detailed by the vendor or NVD.

## Impact

Successful exploitation results in a denial of service, rendering the WS_FTP service unresponsive to legitimate users.

## Recommendation

* Patch affected systems by upgrading to WS_FTP Server version 2025.0.5 or later.
* Audit internet-facing WS_FTP Server instances to ensure they are not accessible to unauthorized networks until patching is completed.
* Monitor service logs for an anomalous spikes in connection requests or sudden service termination events that may indicate exploitation attempts.
