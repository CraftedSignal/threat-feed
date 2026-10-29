---
brief_id: brief-2026-10-29-usp-ultimate-screenshot-painter
event_id: brief-2026-10-29-usp-ultimate-screenshot-painter
revision: 1
activity_at: "2026-10-29T21:07:45Z"
title: 'USP Ultimate Screenshot Painter: Insecure file permission handling (CVE-2026-107042)'
slug: 2026-10-usp-ultimate-screenshot-painter
description: USP Ultimate Screenshot Painter version 240213.009 contains an insecure permission flaw that allows unauthorized actors to move or overwrite files in private storage via crafted content URIs.
date: "2026-10-29T21:07:45Z"
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
  validation_status: Source-based vulnerability details reviewed
cpes:
  - cpe:2.3:a:usp:ultimate_screenshot_painter:240213.009:*:*:*:*:*:*:*
vendors:
  - USP
products:
  - Ultimate Screenshot Painter (240213.009)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Insecure permissions in USP Ultimate Screenshot Painter versionCode 240213.009 allows unauthorized attackers to move or overwrite files in another user's private storage via supplying a crafted content URI.
    confidence_band: high
cves:
  - id: CVE-2026-107042
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107042
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify unauthorized access to internal private storage paths by USP Ultimate Screenshot Painter
      technique_id: T1068
      data_needed:
        - Android system logs (logcat) for file access violations
        - Application sandboxing event logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability allows moving or overwriting files in another user private storage via crafted content URIs.
  mitigation_plan:
    - priority: immediate
      action: Restrict or remove USP Ultimate Screenshot Painter version 240213.009 from corporate-managed mobile devices
      owner: IT Operations
      addresses: CVE-2026-107042
      evidence: Vulnerability allows unauthorized modification of private storage files.
---

USP Ultimate Screenshot Painter, specifically versionCode 240213.009, is vulnerable to an insecure permission issue. An attacker can exploit this flaw by providing a crafted content URI to the application, enabling them to move or overwrite files within the private storage directories of other users. No patch or fixed version has been disclosed by the vendor in the initial advisory.

## Impact
Successful exploitation allows for unauthorized modification of sensitive files or data residing in private application storage, potentially leading to data loss or integrity compromise for other users on the same device.

## Recommendation
- Inventory all Android devices currently running USP Ultimate Screenshot Painter version 240213.009.
- Implement mobile device management (MDM) policies to restrict the application if it is deemed high-risk to the environment.
- Monitor the vendor's official channels for a security patch addressing CVE-2026-107042 and upgrade immediately upon release.
