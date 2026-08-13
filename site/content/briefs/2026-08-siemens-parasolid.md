---
title: Out-of-Bounds Read Vulnerability in Siemens Parasolid
slug: 2026-08-siemens-parasolid
description: Siemens Parasolid contains an out-of-bounds read vulnerability (CVE-2026-64629) in its X_T file parsing logic that can lead to arbitrary code execution or application crashes.
date: "2026-08-13T16:51:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - industrial-control-systems
  - ics
  - cve-2026-64629
vendors:
  - Siemens
products:
  - Parasolid
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The affected applications contains an out of bounds read vulnerability while parsing specially crafted X_T files. This could allow an attacker to execute code in the context of the current process.
    confidence_band: high
cves:
  - id: CVE-2026-64629
    cvss: 7.8
    epss: 0.00113
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-225-10-0
  - https://www.cve.org/CVERecord?id=CVE-2026-64629
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Parasolid V38.0 to V38.0.235 and V38.1 to V38.1.230
      owner: IT Operations
      due: 72h
      evidence: Vendor fix section in the CISA advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict file system permissions and implement application whitelisting for CAD-related file formats
      owner: IT Operations
      addresses: CVE-2026-64629
      evidence: CISA recommended practices
---

Siemens Parasolid is affected by an out-of-bounds read vulnerability, tracked as CVE-2026-64629, which occurs when the application parses specially crafted X_T (Parasolid Transmit) files. The vulnerability stems from improper boundary checking during the ingestion of these CAD data files. An attacker capable of delivering a malicious X_T file to a user or system running an affected version of Parasolid could trigger memory corruption, resulting in either a denial-of-service via application crash or potential arbitrary code execution within the security context of the host process. This vulnerability affects Parasolid version 38.0 (before 38.0.235) and version 38.1 (before 38.1.230). Given that Parasolid is widely used in CAD/CAM/CAE software across critical manufacturing sectors, organizations should prioritize patching to the latest vendor-supplied versions.

## Impact

Successful exploitation allows for arbitrary code execution or service disruption within the context of the user running the CAD software. This vulnerability is particularly relevant to critical manufacturing environments where CAD/CAM tools are integrated into design and production workflows. Exploitation requires user interaction to open a malicious file, but the impact includes full compromise of the local application process.

## Recommendation

* Apply the security patches provided by Siemens immediately for all affected versions of Parasolid.
* Update Parasolid V38.0 installations to V38.0.235 or later.
* Update Parasolid V38.1 installations to V38.1.230 or later.
* Utilize the Siemens operational guidelines for Industrial Security to segment CAD workstations from critical control networks and minimize the attack surface of systems running Parsolid-based applications.
