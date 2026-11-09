---
brief_id: brief-2026-11-09-nasa-jpl-ion-dtn-overflow-89345e21
event_id: brief-2026-11-09-nasa-jpl-ion-dtn-overflow-89345e21
revision: 1
activity_at: "2026-11-09T19:51:51Z"
title: 'NASA JPL ION-DTN: Datagram Retransmission layer heap corruption (CVE-2026-124001)'
slug: 2026-11-nasa-jpl-ion-dtn-overflow-89345e21
description: NASA JPL ION-DTN versions 2.2.1b through 4.2.0 contain an integer overflow vulnerability in the DGR convergence layer that allows remote code execution via heap memory corruption.
date: "2026-11-09T19:51:51Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:nasa:ion-dtn:*:*:*:*:*:*:*:*
vendors:
  - NASA
products:
  - ION-DTN (2.2.1b through 4.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can exploit the dgr_receive API's unchecked memcpy operation... to trigger an out-of-bounds write, leading to denial of service or potential remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-124001
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124001
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all deployments of ION-DTN and restrict access to DGR convergence layer endpoints.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability in Datagram Retransmission layer requires network/IPC isolation to mitigate remote exploitation.
  hunt_leads:
    - lead: Monitor ION-DTN application logs or system crash dumps for repeated segmentation faults or process crashes within the DGR convergence layer.
      technique_id: T1203
      data_needed:
        - Application crash logs
        - Systemd/syslog service failure events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation results in denial of service via out-of-bounds write.
  mitigation_plan:
    - priority: immediate
      action: Apply patch for CVE-2026-124001 once released by NASA JPL.
      owner: IT Operations
      addresses: CVE-2026-124001
      evidence: CVE-2026-124001 vulnerability details
---

NASA JPL ION-DTN versions 2.2.1b through 4.2.0 contain an integer overflow vulnerability in the Datagram Retransmission (DGR) convergence layer. An attacker can supply a crafted 64-bit svcDataLength value that wraps during a 32-bit allocation size calculation. This leads to an out-of-bounds heap write during the dgr_receive API memcpy operation.

## Impact
Successful exploitation allows for denial of service (process crash) or potential remote code execution on systems processing DGR traffic.

## Recommendation
- Upgrade to a patched version of ION-DTN once released by the NASA JPL maintainers.
- Until patched, restrict access to the DGR convergence layer by isolating internal IPC or custom transport endpoints to trusted network segments only.
- Monitor service stability for frequent, unexpected restarts of the ION-DTN process, which may indicate crash-based denial of service attempts.
