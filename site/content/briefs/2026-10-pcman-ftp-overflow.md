---
title: Buffer Overflow Vulnerability in PCMan FTP Server
slug: 2026-10-pcman-ftp-overflow
description: PCMan FTP Server versions through 2.0.7 contain a buffer overflow vulnerability in the PORT command handler that allows remote attackers to execute arbitrary code or trigger a denial of service.
date: "2026-10-14T18:33:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pcman:ftp_server:*:*:*:*:*:*:*:*
vendors:
  - PCMan
products:
  - FTP Server (<= 2.0.7)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1211
    technique_name: Exploitation for Defense Evasion
    evidence: The manipulation results in buffer overflow.
    confidence_band: high
cves:
  - id: CVE-2016-15060
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-15060
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Decommission or replace PCMan FTP Server (<= 2.0.7) on all enterprise systems.
      owner: IT Operations
      due: 72h
      evidence: Source documents CVE-2016-15060 affecting legacy software versions.
  mitigation_plan:
    - priority: immediate
      action: Block or restrict access to TCP port 21 on all internal network segments hosting this software.
      owner: IT Operations
      addresses: CVE-2016-15060
      evidence: Remote exploitability of the PORT command handler.
---

PCMan FTP Server versions up to and including 2.0.7 are vulnerable to a buffer overflow vulnerability within the PORT command handler. This flaw allows a remote, unauthenticated attacker to send a specially crafted request that triggers memory corruption. The vulnerability stems from improper bounds checking when processing the PORT command, which facilitates the execution of arbitrary code or results in a service crash. With public exploit material available, defenders must prioritize patching or isolating instances of this legacy FTP server, as it lacks modern memory protections and presents a significant remote code execution risk.

## Impact

Successful exploitation of this vulnerability leads to complete compromise of the hosting server via arbitrary code execution or results in persistent denial of service. The vulnerability affects all deployments of PCMan FTP Server version 2.0.7 and earlier, which are commonly found in legacy environments or misconfigured test setups.

## Recommendation

- Upgrade PCMan FTP Server to a supported, secure alternative, as version 2.0.7 is end-of-life and contains known unpatched vulnerabilities.
- Implement network segmentation to restrict access to FTP services to authorized IP ranges only.
- Monitor server logs for unexpected process crashes or anomalous traffic patterns directed at the FTP port (default TCP 21) that deviate from standard file transfer sequences.
