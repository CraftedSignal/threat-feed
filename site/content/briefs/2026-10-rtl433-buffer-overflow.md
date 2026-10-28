---
brief_id: brief-2026-10-28-rtl433-buffer-overflow
event_id: brief-2026-10-28-rtl433-buffer-overflow
revision: 1
activity_at: "2026-10-28T08:26:39Z"
title: 'rtl_433: Stack-based buffer overflow in proflame2_mc (CVE-2026-117609)'
slug: 2026-10-rtl433-buffer-overflow
description: rtl_433 versions up to 25.12 contain a stack-based buffer overflow in the proflame2_mc function that allows attackers to trigger memory corruption via malicious OOK radio signals or input files.
date: "2026-10-28T08:26:39Z"
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
  validation_status: Source verified; no IOCs or specific detection signatures provided in original advisory.
cpes:
  - cpe:2.3:a:rtl_433:rtl_433:*:*:*:*:*:*:*:*
tags:
  - buffer-overflow
  - vulnerability
  - rtl_433
vendors:
  - rtl_433
products:
  - rtl_433 (<= 25.12)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can transmit a crafted OOK radio signal or supply a crafted signal file to crash rtl_433 and corrupt stack memory, enabling control-flow hijacking.
    confidence_band: high
cves:
  - id: CVE-2026-117609
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117609
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch rtl_433 to the latest version once available.
      owner: IT Operations
      due: 7d
      evidence: Vulnerability in rtl_433 up to 25.12.
  hunt_leads:
    - lead: Hunt for crash logs or segmentation faults involving the rtl_433 binary.
      technique_id: T1203
      data_needed:
        - syslog
        - dmesg
        - application error logs
      priority: medium
      confidence: medium
      disposition: monitor-only
      evidence: The overflow can cause the application to crash.
  mitigation_plan:
    - priority: immediate
      action: Verify compiler flags to ensure binaries are built with stack canaries.
      owner: IT Operations
      addresses: CVE-2026-117609
      evidence: Exploitability depends on the lack of stack canaries.
---

A stack-based buffer overflow vulnerability exists in the `proflame2_mc()` function of rtl_433 (all versions through 25.12). The issue occurs when the application processes more than seven Manchester-coded words. An attacker within radio range can transmit a crafted On-Off Keying (OOK) signal or provide a malformed signal file to trigger the overflow. This can result in application crashes or, if the binary is compiled without stack canaries, potential control-flow hijacking.

## Impact
Successful exploitation allows for the crash of the rtl_433 service or potential arbitrary code execution, depending on the compiler protections enabled for the specific deployment.

## Recommendation
- Upgrade rtl_433 to a version that patches the `proflame2_mc()` function, or monitor the project repository for the official security release addressing this vulnerability.
- Audit current deployments to determine if they are compiled with stack protection (e.g., `-fstack-protector` or `-fstack-protector-strong`) to mitigate the risk of arbitrary code execution.
- Restrict the input sources for rtl_433 if possible, particularly by verifying the integrity of signal capture files before processing them.
