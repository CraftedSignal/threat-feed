---
title: Multiple Memory Corruption Vulnerabilities in Siemens Solid Edge
slug: 2026-08-siemens-solid-edge-vulns
description: Siemens Solid Edge is affected by multiple memory corruption vulnerabilities, including out-of-bounds read/write and use-after-free, allowing arbitrary code execution via specially crafted PAR, PSM, or DFT files.
date: "2026-08-13T16:53:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - critical-manufacturing
  - memory-corruption
  - cve-report
vendors:
  - Siemens
products:
  - Solid Edge SE2025
  - Solid Edge SE2026
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This could allow an attacker to execute code in the context of the current process.
    confidence_band: high
cves:
  - id: CVE-2026-50058
    cvss: 7.8
    epss: 0.00113
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-225-12
  - https://www.cve.org/CVERecord?id=CVE-2026-50058
  - https://www.cve.org/CVERecord?id=CVE-2026-50059
  - https://www.cve.org/CVERecord?id=CVE-2026-50060
  - https://www.cve.org/CVERecord?id=CVE-2026-50061
  - https://www.cve.org/CVERecord?id=CVE-2026-50062
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Siemens Solid Edge to the versions specified in the remediation guide
      owner: IT Operations
      due: 72h
      evidence: Vendor remediation recommendations from CISA advisory
  mitigation_plan:
    - priority: immediate
      action: Enforce strict document intake policies for CAD files from untrusted sources
      owner: IT Operations
      addresses: CVE-2026-50058, CVE-2026-50059, CVE-2026-50060, CVE-2026-50061, CVE-2026-50062, CVE-2026-50063, CVE-2026-50064
      evidence: Technical advisory concerning file parsing vulnerabilities
---

Siemens has disclosed seven vulnerabilities affecting Solid Edge SE2025 and SE2026, stemming from improper memory handling during the parsing of proprietary file formats (PAR, PSM, and DFT). The vulnerabilities - identified as CVE-2026-50058, CVE-2026-50059, CVE-2026-50060, CVE-2026-50061, CVE-2026-50062, CVE-2026-50063, and CVE-2026-50064 - include out-of-bounds read/write errors and use-after-free conditions. These flaws reside within the application's file parsing logic and can be leveraged by an attacker to trigger application crashes or execute arbitrary code in the context of the user running the software. As these files are frequently shared in engineering and manufacturing environments, this represents a significant risk for organizations within the Critical Manufacturing sector. Users must update to Solid Edge SE2025 V225.0.15 or SE2026 V226.0.7 or later to mitigate these issues.

## Impact

Successful exploitation of these vulnerabilities could result in full system compromise for the affected user's workstation through arbitrary code execution. These vulnerabilities primarily affect the Critical Manufacturing sector globally. The impact ranges from localized application crashes causing denial of service in design workflows to complete code execution, which could facilitate lateral movement or the theft of sensitive engineering data stored within the CAD environment.

## Recommendation

* Update all instances of Siemens Solid Edge SE2025 to V225.0.15 or later immediately.
* Update all instances of Siemens Solid Edge SE2026 to V226.0.7 or later immediately.
* Implement file integrity monitoring and restrict the execution of Solid Edge files from untrusted or external sources within the enterprise environment.
* Monitor for abnormal process behavior or unexpected crashes of the Solid Edge application binaries, which may indicate attempted exploitation of these memory corruption flaws.
