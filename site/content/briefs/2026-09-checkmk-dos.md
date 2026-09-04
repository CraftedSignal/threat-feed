---
title: Checkmk Agent Receiver Denial of Service Vulnerability
slug: 2026-09-checkmk-dos
description: A vulnerability in the Checkmk Agent Receiver allows a remote, authenticated attacker to trigger a Denial of Service condition on the affected monitoring infrastructure.
date: "2026-09-04T18:06:30Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:checkmk:checkmk:*:*:*:*:*:*:*:*
  - cpe:2.3:a:pylonsproject:webob:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - cve
vendors:
  - Checkmk
products:
  - Checkmk Agent Receiver
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A vulnerability in the Checkmk Agent Receiver allows a remote, authenticated attacker to trigger a Denial of Service condition on the affected monitoring infrastructure.
    confidence_band: high
cves:
  - id: CVE-2024-42353
    cvss: 6.1
    epss: 0.00527
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3192
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium_term
      action: Upgrade Checkmk Agent Receiver to the version specified by the vendor security advisory addressing CVE-2024-42353.
      owner: IT Operations
      addresses: CVE-2024-42353
      evidence: Source documentation of vulnerability CVE-2024-42353.
---

The BSI has reported a vulnerability (CVE-2024-42353) affecting the Checkmk Agent Receiver. This vulnerability permits a remote, authenticated attacker to induce a Denial of Service (DoS) condition on the monitoring system. The issue resides within the mechanism that handles incoming agent data. Because successful exploitation requires an authenticated session, the primary risk involves users with established credentials - such as compromised service accounts or malicious insiders - who can disrupt monitoring services, potentially leading to a lack of visibility into system health or operational failures within the monitored infrastructure. Defenders should review access controls to the Agent Receiver and verify that systems are patched to versions addressing this flaw, as identified by the vendor.

## Impact

Successful exploitation results in the disruption of the Checkmk monitoring service, preventing IT administrators from receiving alerts or monitoring the status of infrastructure nodes. This can lead to significant monitoring gaps during critical production outages. The scope of impact is limited to organizations utilizing Checkmk, specifically those where Agent Receiver services are reachable by entities possessing valid, though potentially low-privileged, credentials.

## Recommendation

Prioritize the identification and patching of all instances running the affected Checkmk Agent Receiver. Consult the vendor security advisory for the specific version that remediates CVE-2024-42353. Review authentication logs to monitor for unusual patterns or privilege usage associated with accounts accessing the Agent Receiver service.
