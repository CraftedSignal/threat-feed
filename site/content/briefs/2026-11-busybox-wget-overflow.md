---
brief_id: brief-2026-11-10-busybox-wget-overflow
event_id: brief-2026-11-10-busybox-wget-overflow
revision: 1
activity_at: "2026-11-10T14:33:59Z"
title: 'BusyBox: Heap-based buffer overflow in wget (CVE-2026-124747)'
slug: 2026-11-busybox-wget-overflow
description: A flaw in the BusyBox wget utility allows remote attackers to trigger a heap-based buffer overflow via crafted FTP file size metadata, potentially leading to arbitrary code execution or denial of service.
date: "2026-11-10T14:33:59Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment validation for BusyBox deployment
cpes:
  - cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*
vendors:
  - BusyBox
products:
  - BusyBox
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A malicious FTP server or an on-path network attacker can exploit this issue by returning crafted file size metadata.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Successful exploitation may allow an attacker to execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-124747
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124747
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all systems utilizing BusyBox wget for FTP file transfers
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects BusyBox wget functionality.
  hunt_leads:
    - lead: Monitor system/application logs for abnormal crashes or segmentation faults of processes executing wget
      technique_id: T1190
      data_needed:
        - syslog
        - dmesg
        - application logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Successful exploitation may allow an attacker to execute arbitrary code or crash the application.
  mitigation_plan:
    - priority: medium
      action: Restrict outbound FTP traffic to trusted servers only
      owner: Network Engineering
      addresses: CVE-2026-124747
      evidence: Attack vector involves malicious FTP server or on-path attacker.
---

BusyBox wget utility contains an integer calculation error when resuming FTP downloads. The utility fails to validate that the resume offset does not exceed the file size reported by the FTP server. An attacker operating a malicious FTP server or performing an on-path network attack can provide crafted file size metadata to trigger a heap-based buffer overflow. This can result in application crashes (DoS) or arbitrary code execution. No patch status is currently reported in the source.

## Impact
Successful exploitation allows for remote code execution or denial of service of the BusyBox wget utility, impacting systems relying on BusyBox for network file transfers.

## Recommendation
- Audit network environments for reliance on BusyBox wget for FTP transfers, particularly in untrusted or external network segments.
- Monitor for unexpected crashes of processes utilizing BusyBox wget.
- Evaluate and deploy patches for BusyBox once released by the maintainers.
