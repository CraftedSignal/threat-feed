---
title: ClingSTUN Linux Backdoor Exploits Public STUN Infrastructure
slug: 2026-10-clingstun-backdoor
description: ClingSTUN is a Linux-based backdoor that leverages public Session Traversal Utilities for NAT (STUN) infrastructure to facilitate unauthorized proxy access and C2 communication.
date: "2026-10-05T18:44:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - linux
  - backdoor
  - c2
  - proxy
  - stun
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: ClingSTUN is a Linux-based backdoor that facilitates unauthorized proxy access by leveraging public STUN (Session Traversal Utilities for NAT) server infrastructure.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: The malware establishes connectivity and command-and-control communication while evading traditional NAT/firewall detection mechanisms, allowing attackers to maintain a persistent proxy relay on compromised devices.
    confidence_band: high
references:
  - https://feeds.fortinet.com/~/971007764/0/fortinet/blog/threat-research
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review outbound network traffic logs for excessive or unauthorized usage of public STUN server ports.
      owner: SOC
      due: 48h
      evidence: Source document identifies STUN abuse as the primary mechanism for C2.
  hunt_leads:
    - lead: Identify long-running Linux processes associated with non-standard binary names or locations that initiate outbound UDP connections to public STUN endpoints.
      technique_id: T1071
      data_needed:
        - Process creation logs (Auditd/eBPF)
        - Network connection logs (Netflow/Zeek/Sysmon for Linux)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Malware utilizes STUN servers for persistent proxy relay.
  mitigation_plan:
    - priority: medium_term
      action: Restrict outbound UDP traffic from internal production servers to specific, trusted STUN/TURN infrastructure.
      owner: IT Operations
      addresses: STUN-based C2 infrastructure
      evidence: Observed usage of public STUN infrastructure for proxying.
---

ClingSTUN is a Linux-based backdoor identified by FortiGuard Labs that abuses public STUN (Session Traversal Utilities for NAT) server infrastructure to establish C2 connectivity. By leveraging the STUN protocol, the malware facilitates persistent proxy relay capabilities on compromised Linux devices. This technique allows the backdoor to bypass standard NAT and firewall inspection, as the traffic mimics legitimate STUN requests used for NAT traversal. This approach enables attackers to maintain a covert proxy relay, potentially turning compromised devices into nodes for wider malicious activity or anonymous data exfiltration. The use of public infrastructure for C2 obfuscation complicates traditional network-based detection, requiring defenders to focus on the behavior of the binary and the specific communication patterns associated with STUN-based tunneling.

## Attack Chain

1. Initial exploitation of a vulnerable Linux-based service or device.
2. Deployment of the ClingSTUN binary onto the target filesystem.
3. Execution of the ClingSTUN process to establish persistence on the infected host.
4. Initialization of the STUN protocol client module within the malware.
5. Transmission of crafted STUN packets to public STUN servers to perform NAT traversal.
6. Establishment of an outbound C2 tunnel through the STUN-facilitated NAT hole.
7. Activation of proxy relay functionality, allowing remote attackers to tunnel traffic through the compromised host.

## Impact

Successful deployment of ClingSTUN results in the creation of a persistent, covert proxy relay on the compromised Linux device. This allows attackers to route arbitrary malicious traffic through the victim network, effectively masking the true origin of their attacks and facilitating unauthorized access to internal resources. The impact includes data exfiltration, lateral movement, and the utilization of victim infrastructure as an anonymization layer for broader campaigns.

## Recommendation

1. Monitor network logs for anomalous STUN traffic originating from servers or internal infrastructure that do not typically require NAT traversal.
2. Implement egress filtering to restrict outbound communication to known, authorized STUN servers.
3. Deploy endpoint monitoring to identify unauthorized binaries executing from common persistence locations on Linux systems.
4. Conduct memory forensics on high-value Linux targets to identify dormant or beaconing proxy processes.
