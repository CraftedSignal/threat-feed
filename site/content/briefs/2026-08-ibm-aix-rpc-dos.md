---
title: Uncontrolled Resource Consumption Vulnerability in IBM AIX and PowerVM VIOS
slug: 2026-08-ibm-aix-rpc-dos
description: IBM AIX and PowerVM VIOS contain a remote, unauthenticated denial-of-service vulnerability (CVE-2026-19446) triggered by sending a crafted UDP packet to an RPC service, resulting in system unavailability.
date: "2026-08-20T23:25:24Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - IBM
products:
  - AIX 7.2
  - AIX 7.3
  - PowerVM VIOS 4.1
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A remote unauthenticated attacker can send a crafted UDP packet to a reachable RPC service, resulting in complete system unavailability and requiring an LPAR restart.
    confidence_band: high
cves:
  - id: CVE-2026-19446
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19446
  - https://www.ibm.com/support/pages/node/7283858
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch affected IBM AIX and PowerVM VIOS systems using vendor-provided updates
      owner: IT Operations
      due: 48h
      evidence: IBM security advisory node 7283858
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to RPC services to trusted subnets only
      owner: IT Operations
      addresses: CVE-2026-19446
      evidence: Mitigation for remote unauthenticated access
---

IBM AIX versions 7.2 and 7.3, along with IBM PowerVM VIOS version 4.1, are affected by a high-severity vulnerability identified as CVE-2026-19446. This vulnerability is classified as an uncontrolled resource consumption flaw (CWE-400). A remote, unauthenticated attacker can exploit this weakness by transmitting a specifically crafted UDP packet to a reachable RPC service on the target system. 

Successful exploitation of this vulnerability results in complete system unavailability. Once the RPC service processes the malicious packet, the affected system enters a state where it can no longer function, necessitating a manual restart of the Logical Partition (LPAR) to restore normal operations. This flaw poses a significant availability risk to environments relying on these IBM infrastructure components. Given the nature of RPC services, defenders should prioritize isolating management interfaces and limiting access to RPC-related ports to authorized internal segments to mitigate the risk of exploitation.

## Impact

Successful exploitation of CVE-2026-19446 leads to a complete denial-of-service on the affected AIX or PowerVM VIOS instance. Because the crash forces an LPAR restart, organizations face operational disruption, potential data loss for unsaved processes, and the need for manual administrative intervention to restore service availability. This impact is significant for enterprise environments that rely on Power Systems for critical workloads.

## Recommendation

- Apply the security patches provided by IBM in the advisory linked below to all affected AIX and PowerVM VIOS instances immediately.
- Review network access controls to restrict access to RPC services, ensuring they are not reachable from untrusted or public-facing network segments.
- Monitor system logs and LPAR status for unexpected restarts or service outages that may indicate an exploitation attempt.
- Deploy network-based monitoring to detect and alert on anomalous or high-volume UDP traffic directed toward RPC service ports on critical IBM infrastructure.
