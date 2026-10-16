---
title: 'CVE-2026-109219: Arbitrary File Upload in Mang Board Plugin for WordPress'
slug: 2026-10-mang-board-upload
description: An arbitrary file upload vulnerability in the Mang Board plugin for WordPress allows unauthenticated attackers to achieve remote code execution by bypassing extension validation.
date: "2026-10-16T06:24:33Z"
lastmod: "2026-10-16T06:25:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:mang_board_project:mang_board:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - web-vulnerability
  - rce
  - web-application-vulnerability
  - stored-xss
vendors:
  - WordPress
products:
  - Mang Board (<= 2.4.4)
  - Mang Board (<= 2.4.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.002
    technique_name: 'Server Software Component: Web Shell'
    evidence: This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-109219
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109219
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109998
rules:
  - title: Detect CVE-2026-109998 Exploitation - Malicious POST to mb_template
    description: Detects potential exploitation attempts of CVE-2026-109998 by monitoring for unauthenticated POST requests to the admin-ajax endpoint targeting the mb_template action with content_reply mode.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all WordPress sites to identify presence of Mang Board plugin
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in Mang Board plugin
  mitigation_plan:
    - priority: immediate
      action: Disable guest post features in Mang Board plugin settings
      owner: IT Operations
      addresses: CVE-2026-109219
      evidence: Exploitation requires the board to be configured to allow guest posts
updates:
  - at: "2026-10-16T06:25:48Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-109998 Exploitation - Malicious POST to mb_template'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109998
---

The Mang Board plugin for WordPress, in all versions up to and including 2.4.4, contains a critical arbitrary file upload vulnerability within the mbw_file_upload function. The vulnerability arises because the function fails to perform adequate file extension validation on the attacker-controlled image_path parameter. While a separate file_name parameter is subject to an allowlist, the logic incorrectly utilizes the basename of the image_path to determine the final filename, effectively bypassing existing security controls.

Because the required nonce for the upload action is printed on public-facing board pages, unauthenticated attackers can scrape this token and proceed with the upload process. When the plugin is configured for guest posts, which is the default setting, remote attackers can upload executable files (such as PHP webshells) to the server. Successful exploitation enables unauthenticated remote code execution, granting attackers full control over the affected WordPress installation. Organizations should prioritize updating the plugin to a patched version once available and ensuring guest post configurations are restricted where possible.
