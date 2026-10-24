---
brief_id: brief-2026-10-24-yootheme-rce
event_id: brief-2026-10-24-yootheme-rce
revision: 1
activity_at: "2026-10-24T00:59:58Z"
title: 'YOOtheme Pro: Unauthenticated Remote Code Execution (CVE-2026-102785)'
slug: 2026-10-yootheme-rce
description: CVE-2026-102785 is a critical unauthenticated remote code execution vulnerability in YOOtheme Pro (versions <= 5.0.52) that allows attackers to write and execute polyglot files via manipulated image processing operations.
date: "2026-10-24T00:59:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified against Sploitus source; requires deployment in lab for rule tuning
cpes:
  - cpe:2.3:a:yootheme:pro:*:*:*:*:*:*:*:*
vendors:
  - YOOtheme
products:
  - YOOtheme Pro (<= 5.0.52)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Fully automatic exploit for the unauthenticated remote code execution in YOOtheme Pro
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.003
    technique_name: Web Shell
    evidence: drops an executable JPEG+PHP polyglot into public media dirs
    confidence_band: high
cves:
  - id: CVE-2026-102785
    epss: 0.00701
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=0FA7C8EE-53B0-5A9E-B882-F46472FD8A17
  - https://sploitus.com/exploit?id=0FA7C8EE-53B0-5A9E-B882-F46472FD8A17&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-102785 - Potential Polyglot PHP Upload in Media Path
    description: Detects the creation of files with .php extensions within common image upload or cache directories, a technique used in CVE-2026-102785 exploitation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all instances of YOOtheme Pro to version 5.0.53
      owner: IT Operations
      due: 24h
      evidence: Fixed in YOOtheme Pro 5.0.53.
  hunt_leads:
    - lead: Search web server access logs for POST requests to image processing paths containing PHP shell syntax or encoded payloads
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The exploit injects unsigned image operations and triggers RCE
  mitigation_plan:
    - priority: immediate
      action: Upgrade YOOtheme Pro to 5.0.53 or higher
      owner: IT Operations
      addresses: CVE-2026-102785
      evidence: Fixed in YOOtheme Pro 5.0.53.
---

CVE-2026-102785 is a critical unauthenticated remote code execution (RCE) vulnerability affecting the YOOtheme Pro extension for Joomla and theme for WordPress. An exploit PoC has been publicly disclosed that leverages signature reuse, image operation injection, and path traversal to write a JPEG+PHP polyglot file to public media directories. YOOtheme has addressed this in version 5.0.53.

## Attack Chain

1. Attacker performs fingerprinting of target websites to identify YOOtheme Pro installations.
2. Attacker identifies a public image URL to obtain a valid signature for the image processing engine.
3. Attacker injects malicious `FROMFILE` and `SAVE` image operations into the processing request.
4. Attacker utilizes path traversal to escape the intended image cache directory.
5. Attacker forces the application to write a JPEG+PHP polyglot file into a public-facing media directory.
6. Attacker triggers code execution by requesting the uploaded file, leading to the deployment of a custom PHP uploader.

## Impact

Successful exploitation allows for full unauthenticated remote code execution, granting attackers the ability to upload shells, exfiltrate data, or compromise the underlying web server.

## Recommendation

- Upgrade YOOtheme Pro to version 5.0.53 or later immediately.
- Implement file integrity monitoring on WordPress/Joomla media and upload directories to detect the creation of unexpected .php or .phtml files.
- Review web server access logs for anomalous requests to image processing endpoints or direct execution of files within media/cache paths.
