---
title: Remote Code Execution in MOOS essential-moos pAntler
slug: 2026-09-moos-pantler-rce
description: The pAntler component in essential-moos versions 10.0.1 and earlier allows unauthenticated attackers to achieve remote code execution by publishing a crafted MISSION_FILE message to the MOOSDB.
date: "2026-09-03T23:25:50Z"
lastmod: "2026-09-03T23:27:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:moos-ivp:essential-moos:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - cve
  - network-security
vendors:
  - MOOS
products:
  - essential-moos (<= 10.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker can trigger this by sending a specially crafted MISSION_FILE message to the MOOSDB.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can send crafted UDP packets to the configured port to inject arbitrary variables into the local MOOS community.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can inject arbitrary variables into the local MOOS community.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can send crafted UDP packets to the configured UDPListen port to trigger an oversized memcpy operation that writes past the destination buffer, causing heap corruption and denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-85427
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85427
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85431
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85436
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate MOOSDB network access to authorized segments
      owner: SOC
      due: 24h
      evidence: Unauthenticated RCE vulnerability via MOOSDB message injection
  mitigation_plan:
    - priority: immediate
      action: Upgrade essential-moos to a patched version post-10.0.1
      owner: IT Operations
      addresses: CVE-2026-85427
      evidence: Vulnerability fixed in releases following 10.0.1
updates:
  - at: "2026-09-03T23:27:36Z"
    level: L2
    summary: added coverage for essential-moos (<= 10.0.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85431
  - at: "2026-09-03T23:27:50Z"
    level: L1
    summary: added coverage for essential-moos (<= 10.0.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85436
---

The MOOS-IvP open-source project essential-moos suite, specifically the pAntler component through version 10.0.1, contains a critical remote code execution vulnerability. pAntler is designed to manage and launch various MOOS processes defined within a mission file. An unauthenticated attacker capable of communicating with the MOOSDB can publish a specially crafted 'MISSION_FILE' message. The pAntler application reads the contents of this message and parses it for 'Run' entries. Due to a lack of authentication and input validation on these entries, pAntler passes the user-supplied strings directly to the execvp() system call, resulting in the execution of arbitrary programs with the privileges of the pAntler process. This vulnerability is significant for autonomous systems and research platforms that utilize the MOOS-IvP architecture, as it allows for full command execution on the host machine.

## Attack Chain

1. Attacker establishes network connectivity to the target MOOSDB port.
2. Attacker crafts a malicious MISSION_FILE message containing arbitrary commands within 'Run' entries.
3. Attacker publishes the crafted message to the MOOSDB via the MOOS protocol.
4. The pAntler component receives the malicious MISSION_FILE message from the MOOSDB.
5. pAntler parses the 'Run' entries within the message without validating the input.
6. pAntler calls the execvp() system call, passing the malicious entries.
7. The operating system executes the attacker-defined program on the host.

## Impact

Successful exploitation allows unauthenticated remote attackers to execute arbitrary programs on systems running affected versions of essential-moos. This can lead to full system compromise, loss of control over autonomous mission software, and data exfiltration. The vulnerability affects research and robotics environments utilizing the MOOS-IvP middleware.

## Recommendation

1. Upgrade the essential-moos software to a version beyond 10.0.1 immediately, if available, or isolate MOOSDB instances from untrusted network segments.
2. Implement network access controls (NAC) to restrict communication with the MOOSDB port to authorized and authenticated mission components only.
3. Audit environments for the use of pAntler and ensure process execution policies are configured to minimize the impact of unauthorized sub-process spawning.
