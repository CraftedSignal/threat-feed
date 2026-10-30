---
brief_id: brief-2026-10-30-gimp-psd-overflow
event_id: brief-2026-10-30-gimp-psd-overflow
revision: 1
activity_at: "2026-10-30T17:36:10Z"
title: 'GIMP: PSD plug-in stack-based buffer overflow (CVE-2026-119528)'
slug: 2026-10-gimp-psd-overflow
description: GIMP contains a stack-based buffer overflow vulnerability in the PSD plug-in image resource header loader, allowing an attacker to execute arbitrary code via a crafted PSD file.
date: "2026-10-30T17:36:10Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source does not provide a fixed version; patch management relies on upstream vendor releases.
cpes:
  - cpe:2.3:a:gimp:gimp:*:*:*:*:*:*:*:*
vendors:
  - GIMP
products:
  - GIMP
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Opening a crafted PSD file can cause a stack-based buffer overflow, leading to a crash and potentially arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-119528
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119528
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  hunt_leads:
    - lead: Identify GIMP process crashes indicating potential exploitation attempts of the PSD plug-in.
      technique_id: T1203
      data_needed:
        - 'Windows Application Event Logs (Event ID 1000: Application Error)'
        - macOS System/Crash logs
        - Linux core dump logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Opening a crafted PSD file can cause a stack-based buffer overflow, leading to a crash.
  mitigation_plan:
    - priority: immediate
      action: Monitor GIMP project releases and update GIMP to the first version containing a patch for CVE-2026-119528.
      owner: IT Operations
      addresses: CVE-2026-119528
      evidence: Opening a crafted PSD file can cause a stack-based buffer overflow, leading to a crash and potentially arbitrary code execution.
---

A vulnerability exists in the GIMP PSD plug-in where the image resource header loader performs an incorrect destination size calculation when copying a resource name into a fixed stack buffer. This flaw enables a stack-based buffer overflow, which can be exploited by an attacker providing a specially crafted PSD file. Successful exploitation may result in an application crash or arbitrary code execution within the context of the GIMP process.

## Impact
An attacker can achieve arbitrary code execution on a target system by convincing a user to open a malicious PSD file in GIMP. The vulnerability also poses a risk of denial-of-service via application crashing.

## Recommendation
1. Audit workstation inventory to identify instances of GIMP where PSD file handling is enabled.
2. Advise users to avoid opening untrusted or unsolicited PSD files until a patch is applied.
3. Monitor for GIMP process crashes on systems that frequently process image files.
4. Monitor official GIMP security releases and apply patches for CVE-2026-119528 as soon as they become available.
