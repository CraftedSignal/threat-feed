---
brief_id: brief-2026-11-10-ettercap-stack-buffer-underwrite
event_id: brief-2026-11-10-ettercap-stack-buffer-underwrite
revision: 1
activity_at: "2026-11-10T02:05:51Z"
title: 'Ettercap: Stack buffer underwrite in telnet dissector (CVE-2026-125406)'
slug: 2026-11-ettercap-stack-buffer-underwrite
description: Ettercap versions through 0.8.4.1 are vulnerable to a stack buffer underwrite in the telnet dissector, which could allow an unauthenticated attacker to corrupt memory and potentially execute arbitrary code with root privileges.
date: "2026-11-10T02:05:51Z"
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
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:ettercap:ettercap:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - network-security
vendors:
  - Ettercap
products:
  - Ettercap (<= 0.8.4.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can send a telnet stream with more backspaces than preceding characters to write below the stack buffer, corrupting the stack of the Ettercap process that normally runs as root.
    confidence_band: high
cves:
  - id: CVE-2026-125406
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125406
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory systems running Ettercap version 0.8.4.1 or earlier
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects Ettercap versions through 0.8.4.1
  hunt_leads:
    - lead: Identify systems listening on TCP port 23 (Telnet) where Ettercap is identified as the listening process
      technique_id: T1068
      data_needed:
        - Host-based process-to-port mapping logs (e.g., netstat, lsof, or EDR process telemetry)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Ettercap is a network interception tool that often runs as root, making it a target for traffic-based exploitation.
  mitigation_plan:
    - priority: immediate
      action: Disable or restrict access to Ettercap instances running on exposed network interfaces
      owner: IT Operations
      addresses: CVE-2026-125406
      evidence: Exploitation occurs via malicious telnet streams processed by the vulnerable dissector
---

Ettercap versions through 0.8.4.1 contain a stack buffer underwrite vulnerability in the telnet dissector located in 'src/dissectors/ec_telnet.c'. The vulnerability exists because the software fails to perform a lower bound check when decrementing the output pointer in response to a backspace character. An attacker providing a malicious telnet stream containing more backspaces than preceding characters can write data below the intended stack buffer. 

## Impact
Successful exploitation allows for memory corruption within the Ettercap process. As Ettercap is frequently executed with root privileges, this vulnerability poses a high risk of arbitrary code execution or denial of service through process crashes.

## Recommendation
- Audit infrastructure to identify and inventory all instances of Ettercap 0.8.4.1 or earlier.
- Prioritize the isolation of systems running Ettercap in untrusted network environments until a patched version is available.
- Implement network-level inspection to identify anomalous telnet traffic patterns (excessive backspace characters) directed at systems running Ettercap.
