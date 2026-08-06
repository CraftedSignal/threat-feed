---
title: Unauthenticated Denial of Service in Ground Station
slug: 2026-08-ground-station-dos
description: Ground Station versions prior to 0.6.0 are susceptible to an unauthenticated denial-of-service vulnerability in the Socket.IO service_control event handler, allowing remote attackers to terminate critical satellite-tracking processes via a restart_service command.
date: "2026-08-06T17:26:01Z"
lastmod: "2026-08-06T23:29:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - remote-code-execution
  - sql-injection
  - ground-station
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
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ground Station prior to 0.6.0 contains an unauthenticated database-destruction and arbitrary-data-injection vulnerability in the Socket.IO server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
    evidence: Allows any unauthenticated network peer to wipe or replace the entire SQLite database by sending a single full_restore command with a caller-supplied SQL blob.
    confidence_band: high
cves:
  - id: CVE-2026-53985
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53985
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53984
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
updates:
  - at: "2026-08-06T23:29:32Z"
    level: L2
    summary: added coverage for Ground Station
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-53984
---

Ground Station software versions prior to 0.6.0 contain a critical vulnerability in the Socket.IO server implementation, specifically within the service_control event handler. This flaw allows any unauthenticated network peer to send a restart_service command to the Socket.IO server, which is configured to listen on TCP port 7000. Due to a combination of missing authentication enforcement and a wildcard Cross-Origin Resource Sharing (CORS) policy, the service accepts and executes the restart command from unauthorized sources. Successful exploitation triggers an immediate termination of the ground-station process, resulting in the loss of all active satellite-tracking sessions, SDR (Software Defined Radio) recording pipelines, signal demodulators, decoders, and hardware rotator controllers. In Docker-based deployments, where containers are often configured to restart automatically upon process failure, an attacker can continuously emit this command to establish a persistent denial-of-service state.

## Impact

The vulnerability poses a severe risk to satellite operations and data integrity. By forcibly terminating the ground-station process, attackers can cause significant operational downtime, interrupting real-time satellite telemetry, SDR data ingestion, and mission-critical tracking tasks. In scenarios where containers are automatically restarted, the persistence of this attack renders the affected infrastructure entirely unavailable for legitimate commands, potentially leading to total loss of communications or orbital control capabilities during critical windows.

## Recommendation

1. Upgrade all instances of Ground Station to version 0.6.0 or later immediately to patch the insecure event handler and correct the authentication logic.
2. Implement network-layer access controls (e.g., firewall rules or VPC security groups) to restrict inbound traffic to TCP port 7000 to only known, trusted administrative IP addresses.
3. Reconfigure the Socket.IO server CORS policy to explicitly define authorized origins rather than using a wildcard, preventing cross-origin exploitation attempts.
