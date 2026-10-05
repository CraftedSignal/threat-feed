---
title: Detection of Unauthorized Remote Access Software via Web Traffic
slug: 2026-10-remote-access-software-usage
description: This detection analytic identifies unauthorized usage of remote access utilities by monitoring web traffic for connections to known domains associated with tools such as AnyDesk, GoToMyPC, LogMeIn, and TeamViewer.
date: "2026-10-05T12:35:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - remote-access
  - network-security
  - T1219
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: Adversaries often use these utilities to maintain unauthorized remote access.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy web traffic logging for remote access domains to SIEM
      owner: Detection Engineering
      due: 72h
      evidence: Source documentation on required network telemetry
  hunt_leads:
    - lead: Identify outbound web traffic to known remote access domains from workstations
      technique_id: T1219
      data_needed:
        - Firewall or Web Proxy logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source analytic identifies unauthorized remote access tool usage
  mitigation_plan:
    - priority: medium_term
      action: Establish a formal process for reviewing and updating the remote access software allowlist
      owner: SOC
      addresses: False positive management for IT remote tools
      evidence: Source explicitly mentions legitimate software false positives
---

Adversaries frequently employ legitimate remote access and monitoring tools (RATs/RMMs) to maintain persistence, conduct command-and-control (C2) communication, and facilitate unauthorized data exfiltration. This threat involves the use of dual-use software - such as AnyDesk, GoToMyPC, LogMeIn, and TeamViewer - which are often indistinguishable from standard administrative traffic unless specific domain indicators are monitored. This analytic focuses on identifying network connections to domains associated with these utilities by mapping web proxy or firewall traffic to the Common Information Model (CIM) Web data model. Defensive teams must differentiate between authorized enterprise IT management activities and malicious actor usage. Success in this detection relies on maintaining a robust allowlist lookup to manage known-good business use cases, as these tools are commonly integrated into modern enterprise workflows.

## Attack Chain

1. Initial access: Adversary gains entry to a target system via phishing, exploit, or credential theft.
2. Staging: Attacker downloads a legitimate remote access installer or portable executable onto the compromised host.
3. Execution: The remote access binary is launched, establishing a connection to its vendor-hosted C2 cloud infrastructure.
4. C2 Established: The host registers with the attacker-controlled panel, providing a unique ID for remote interaction.
5. Persistence: The actor configures the software to run automatically upon system startup to maintain long-term access.
6. Action on Objective: The attacker uses the remote interface to browse files, exfiltrate sensitive data, or deploy additional malware like ransomware.

## Impact

Successful exploitation allows for complete remote control of compromised systems, enabling attackers to bypass traditional perimeter security, exfiltrate intellectual property, and deploy destructive payloads like ransomware. This technique is observed across multiple sectors and is a standard component in the toolsets of major ransomware operations and organized cybercriminal groups.

## Recommendation

Prioritize the implementation of network-based monitoring for known remote access software domains to identify unauthorized usage.
- Process network logs (Firewall/Proxy) and map them to the Web data model using the Splunk CIM to ensure compatibility with detection logic.
- Implement a lookup-based allowlist (remote_access_software_usage_exception.csv) to manage legitimate enterprise use of these tools and reduce false positives.
- Investigate any detected connections from unexpected source IPs or user accounts using the provided drilldown searches.
- Integrate Asset and Identity (A&I) lookups to automatically suppress alerts for known IT administration endpoints.
