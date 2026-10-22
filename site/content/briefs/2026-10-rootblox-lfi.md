---
brief_id: brief-2026-10-22-rootblox-lfi
event_id: brief-2026-10-22-rootblox-lfi
revision: 1
activity_at: "2026-10-22T12:49:22Z"
title: CozyThemes Rootblox WordPress plugin Local File Inclusion (CVE-2026-112832)
slug: 2026-10-rootblox-lfi
description: The CozyThemes Rootblox plugin for WordPress, versions 1.0.6 and earlier, contains a Local File Inclusion vulnerability that allows unauthenticated remote attackers to include arbitrary files, potentially leading to remote code execution.
date: "2026-10-22T12:49:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Source corroborated by Patchstack; exploit publicly available.
cpes:
  - cpe:2.3:a:cozythemes:rootblox:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - lfi
  - web-application
  - vulnerability
vendors:
  - CozyThemes
products:
  - Rootblox (<= 1.0.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in CozyThemes Rootblox rootblox allows PHP Local File Inclusion.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: This flaw allows an unauthenticated remote attacker to include arbitrary files, potentially leading to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-112832
    cvss: 9.8
    kev_status: "false"
references:
  - https://patchstack.com/database/wordpress/plugin/rootblox/vulnerability/wordpress-rootblox-plugin-1-0-6-local-file-inclusion-vulnerability?_s_id=cve
  - https://sploitus.com/exploit?id=CVE-2026-112832
  - https://sploitus.com/exploit?id=CVE-2026-112832&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory and disable Rootblox plugin versions <= 1.0.6 across the environment.
      owner: IT Operations
      due: 24h
      evidence: Confirmed vulnerable version range in advisory.
  mitigation_plan:
    - priority: immediate
      action: Uninstall or disable the vulnerable Rootblox plugin.
      owner: IT Operations
      addresses: CVE-2026-112832
      evidence: Plugin version 1.0.6 is confirmed vulnerable.
---

CVE-2026-112832 is a critical Local File Inclusion (LFI) vulnerability discovered in the CozyThemes Rootblox plugin for WordPress, affecting all versions up to and including 1.0.6. The vulnerability stems from improper control of filename parameters used in PHP include or require statements, allowing unauthenticated attackers to read sensitive files on the server or achieve Remote Code Execution (RCE). As of October 22, 2026, proof-of-concept exploit code is publicly available.

## Impact

Successful exploitation allows unauthenticated remote attackers to achieve high confidentiality, integrity, and availability impact, typically resulting in full site compromise through arbitrary PHP code execution or unauthorized access to sensitive application files.

## Recommendation

- Identify all WordPress instances running the 'Rootblox' plugin.
- Deactivate and uninstall the Rootblox plugin immediately if it is version 1.0.6 or earlier until a secure version is confirmed available by the vendor.
- Review web server access logs for requests containing path traversal sequences (e.g., ../) targeting PHP file inclusion parameters commonly used by the plugin.
