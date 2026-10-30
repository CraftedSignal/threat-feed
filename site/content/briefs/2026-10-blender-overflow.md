---
brief_id: brief-2026-10-30-blender-overflow
event_id: brief-2026-10-30-blender-overflow
revision: 1
activity_at: "2026-10-30T17:37:37Z"
title: 'Blender: Heap buffer overflow in thumbnail extractor (CVE-2026-119719)'
slug: 2026-10-blender-overflow
description: Blender versions prior to 4.5.15 and 5.x prior to 5.2.3 contain a heap buffer overflow in the thumbnail extractor that can lead to remote code execution when parsing maliciously crafted .blend files.
date: "2026-10-30T17:37:37Z"
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
cpes:
  - cpe:2.3:a:blender:blender:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - blender
vendors:
  - Blender
products:
  - Blender (< 4.5.15)
  - Blender (5.x < 5.2.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can craft a .blend file with malicious TEST block dimensions that trigger an out-of-bounds write when blender-thumbnailer or the Windows shell extension previews it, causing crashes or code execution.
    confidence_band: high
cves:
  - id: CVE-2026-119719
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119719
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all systems with Blender installed to identify versions prior to 4.5.15 or 5.2.3.
      owner: IT Operations
      due: 24h
      evidence: Source advisory identifies specific vulnerable version ranges.
  hunt_leads:
    - lead: Monitor for crashes of blender-thumbnailer or shell-extension host processes when handling .blend files.
      technique_id: T1203
      data_needed:
        - Windows Application Event Logs (Event ID 1000 - Application Error)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The advisory states the vulnerability causes crashes when processing crafted .blend files.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Blender to 4.5.15 or 5.2.3.
      owner: IT Operations
      addresses: CVE-2026-119719
      evidence: NVD advisory release notes.
---

Blender contains a heap-based buffer overflow vulnerability (CVE-2026-119719) located within the thumb_data_vertical_flip() function of the blend file thumbnail extractor. The vulnerability is triggered by a 32-bit integer overflow when processing a specially crafted .blend file.

## Impact

Successful exploitation allows an attacker to achieve arbitrary code execution or cause an application crash. The vulnerability is triggered when the blender-thumbnailer or a Windows shell extension processes a .blend file containing malicious TEST block dimensions.

## Recommendation

* Upgrade Blender installations to version 4.5.15 or later, or 5.2.3 or later, to address the vulnerability.
* In environments where patching is delayed, restrict the automatic previewing of .blend files by disabling thumbnail shell extensions or untrusted file processing utilities.
