---
title: Unauthenticated Denial of Service in Ground Station
slug: 2026-08-ground-station-dos
description: Ground Station versions prior to 0.6.0 are susceptible to an unauthenticated denial-of-service vulnerability in the Socket.IO service_control event handler, allowing remote attackers to terminate critical satellite-tracking processes via a restart_service command.
date: "2026-08-06T17:26:01Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - Ground Station
products:
  - Ground Station
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Ground Station prior to 0.6.0 contains an unauthenticated denial-of-service vulnerability in the Socket.IO server's service_control event handler that allows any unauthenticated network peer to forcibly terminate the ground-station process.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Attackers can connect to the Socket.IO server on port 7000 without credentials due to disabled authentication enforcement and a wildcard CORS policy.
    confidence_band: high
cves:
  - id: CVE-2026-53985
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53985
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Ground Station software to version 0.6.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-53985 vendor patch availability
  mitigation_plan:
    - priority: immediate
      action: Restrict TCP port 7000 access via firewall
      owner: Security Operations
      addresses: CVE-2026-53985
      evidence: Unauthenticated socket access on port 7000
---

Ground Station software versions prior to 0.6.0 contain a critical vulnerability in the Socket.IO server implementation, specifically within the service_control event handler. This flaw allows any unauthenticated network peer to send a restart_service command to the Socket.IO server, which is configured to listen on TCP port 7000. Due to a combination of missing authentication enforcement and a wildcard Cross-Origin Resource Sharing (CORS) policy, the service accepts and executes the restart command from unauthorized sources. Successful exploitation triggers an immediate termination of the ground-station process, resulting in the loss of all active satellite-tracking sessions, SDR (Software Defined Radio) recording pipelines, signal demodulators, decoders, and hardware rotator controllers. In Docker-based deployments, where containers are often configured to restart automatically upon process failure, an attacker can continuously emit this command to establish a persistent denial-of-service state.

## Impact

The vulnerability poses a severe risk to satellite operations and data integrity. By forcibly terminating the ground-station process, attackers can cause significant operational downtime, interrupting real-time satellite telemetry, SDR data ingestion, and mission-critical tracking tasks. In scenarios where containers are automatically restarted, the persistence of this attack renders the affected infrastructure entirely unavailable for legitimate commands, potentially leading to total loss of communications or orbital control capabilities during critical windows.

## Recommendation

1. Upgrade all instances of Ground Station to version 0.6.0 or later immediately to patch the insecure event handler and correct the authentication logic.
2. Implement network-layer access controls (e.g., firewall rules or VPC security groups) to restrict inbound traffic to TCP port 7000 to only known, trusted administrative IP addresses.
3. Reconfigure the Socket.IO server CORS policy to explicitly define authorized origins rather than using a wildcard, preventing cross-origin exploitation attempts.
