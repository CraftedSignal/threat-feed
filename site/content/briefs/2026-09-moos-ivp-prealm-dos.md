---
title: Resource Exhaustion in MOOS-IvP pRealm via REALMCAST_REQ
slug: 2026-09-moos-ivp-prealm-dos
description: MOOS-IvP pRealm version 24.8.1 and earlier is vulnerable to a denial-of-service attack due to improper validation of REALMCAST_REQ subscriptions, allowing attackers to exhaust system resources.
date: "2026-09-03T23:28:55Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:moos-ivp:prealm:*:*:*:*:*:*:*:*
vendors:
  - MOOS-IvP
products:
  - pRealm (<= 24.8.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can register long-lived pipeways with many variables to cause pRealm to generate excessive output indefinitely, exhausting system resources.
    confidence_band: high
cves:
  - id: CVE-2026-85447
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85447
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Review MOOS-IvP deployment and restrict access to the communication bus.
      owner: Network Security
      due: 48h
      evidence: Mitigation of unbounded access to pRealm variables.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the version succeeding 24.8.1 once provided by the vendor.
      owner: IT Operations
      addresses: CVE-2026-85447
      evidence: NVD vulnerability disclosure.
---

MOOS-IvP pRealm, a component used in autonomous marine vehicle systems, contains a vulnerability (CVE-2026-85447) that allows for the exhaustion of system resources. The issue stems from the pRealm process accepting REALMCAST_REQ subscriptions without enforcing limits on the subscription duration or the number of variables requested.

An attacker with network access to the MOOS community can send a malformed or malicious REALMCAST_REQ message containing an unbounded duration or an excessively large variable list. By registering these long-lived pipeways, the attacker forces pRealm to process and generate output indefinitely. This unchecked resource consumption can lead to severe performance degradation or total service unavailability for the pRealm process, impacting the stability and operation of the MOOS-IvP environment. This vulnerability affects all versions up to and including 24.8.1.

## Impact

Successful exploitation leads to a denial-of-service condition for the pRealm component. In the context of autonomous marine vehicles, this can compromise the ability of the system to process real-time environmental data or command-and-control telemetry, potentially causing critical system instability or operational failure.

## Recommendation

Prioritized actions for security and engineering teams:

- Update MOOS-IvP to the latest version that contains a patch for CVE-2026-85447.
- Implement network-level segmentation to restrict access to the MOOS community communications, ensuring only trusted systems can submit subscription requests to pRealm.
- Monitor system-level resource usage for the pRealm process, specifically looking for sustained high CPU and memory utilization that aligns with periods of unusual network traffic.
