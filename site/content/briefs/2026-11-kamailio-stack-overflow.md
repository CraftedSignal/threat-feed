---
brief_id: brief-2026-11-02-kamailio-stack-overflow
event_id: brief-2026-11-02-kamailio-stack-overflow
revision: 1
activity_at: "2026-11-02T19:49:15Z"
title: 'Kamailio: Stack-based buffer overflow in ims_qos_npn module (CVE-2026-106804)'
slug: 2026-11-kamailio-stack-overflow
description: A stack-based buffer overflow in the Kamailio ims_qos_npn module allows an unauthenticated remote attacker to cause a denial-of-service condition via a crafted SIP REGISTER request.
date: "2026-11-02T19:49:15Z"
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
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:kamailio:kamailio:6.1.3:*:*:*:*:*:*:*
  - cpe:2.3:a:kamailio:kamailio:6.1.4:*:*:*:*:*:*:*
vendors:
  - Kamailio
products:
  - Kamailio (v6.1.3, v6.1.4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: An unauthenticated remote attacker can trigger the vulnerability with a crafted SIP REGISTER request, causing stack corruption and termination of the affected Kamailio instance, resulting in denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-106804
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106804
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify all Kamailio instances running version 6.1.3 or 6.1.4.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects Kamailio v6.1.3 and v6.1.4.
  hunt_leads:
    - lead: Search SIP traffic logs for REGISTER requests containing unusually long host strings in the Via header.
      technique_id: T1210
      data_needed:
        - Kamailio SIP transaction logs
        - Full packet capture (PCAP) of incoming SIP traffic
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The flaw occurs within the w_rx_aar_register() function, which fails to validate the length of the host field in the SIP Via header.
  mitigation_plan:
    - priority: immediate
      action: Disable the ims_qos_npn module if not strictly required for business operations.
      owner: IT Operations
      addresses: CVE-2026-106804
      evidence: Vulnerability is isolated to the ims_qos_npn module.
---

A stack-based buffer overflow vulnerability exists in Kamailio versions 6.1.3 and 6.1.4 within the ims_qos_npn module. The function w_rx_aar_register() copies the host field from a SIP Via header into a fixed 46-byte stack buffer without performing adequate length validation. An unauthenticated, remote attacker can trigger this vulnerability by sending a specially crafted SIP REGISTER request to the server.

## Impact
The primary observed impact is application instability and process termination, resulting in a denial-of-service condition for the affected Kamailio instance. While the vulnerability involves a stack-based buffer overflow, the report identifies the outcome as denial of service.

## Recommendation
- Inventory all Kamailio instances to identify deployments running versions 6.1.3 or 6.1.4.
- Monitor logs for malformed SIP traffic targeting the ims_qos_npn module.
- Upgrade affected Kamailio instances to a version where this vulnerability is remediated once a patch is available from the vendor.
