---
title: OS Command Injection in image_optimizer Ruby Gem
slug: 2026-10-image-optimizer-rce
description: The image_optimizer Ruby gem, versions 1.3.0 through 1.9.0, is vulnerable to OS command injection via the ImageOptimizer#identify_format method when processing malicious, user-supplied image paths.
date: "2026-10-08T19:40:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:image_optimizer_project:image_optimizer:*:*:*:*:*:ruby:*:*
products:
  - image_optimizer (1.3.0 - 1.9.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can exploit this by supplying a maliciously crafted image path containing shell metacharacters that are then executed via Ruby backticks.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: The image_optimizer Ruby gem contains an OS command injection vulnerability in ImageOptimizer#identify_format that allows attackers to execute commands.
    confidence_band: high
cves:
  - id: CVE-2026-107704
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107704
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade image_optimizer to version > 1.9.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-107704 reports vulnerable versions 1.3.0 - 1.9.0
  mitigation_plan:
    - priority: immediate
      action: Sanitize user-provided input for filenames passed to the image_optimizer gem
      owner: Application Security
      addresses: CVE-2026-107704
      evidence: Source notes injection via shell metacharacters like ; in image paths
---

The image_optimizer Ruby gem, specifically versions 1.3.0 through 1.9.0, contains an OS command injection vulnerability located within the ImageOptimizer#identify_format method. This flaw manifests when the gem is configured with the 'identify' option enabled. An attacker capable of influencing the image path parameter (such as through a user-controlled file upload form or filename input) can inject arbitrary shell metacharacters, including semicolons. These injected characters are subsequently processed by Ruby's backtick execution operator, allowing the commands to run with the same privileges as the underlying Ruby application process. This vulnerability presents a significant risk to any Ruby-based web application that utilizes this gem for image processing tasks, as it potentially grants unauthenticated remote attackers the ability to execute arbitrary code on the host server.

## Impact

Successful exploitation of CVE-2026-107704 allows an unauthenticated attacker to execute arbitrary OS commands on the host server. Depending on the privileges of the Ruby application process, this could lead to full system compromise, data exfiltration, or the deployment of persistent malware. Organizations using vulnerable versions of the image_optimizer gem in public-facing applications are at high risk.

## Recommendation

Prioritized actions for development and security teams include:
- Upgrade the image_optimizer Ruby gem to a version beyond 1.9.0 immediately to mitigate CVE-2026-107704.
- Review all web application code paths that pass user-supplied input to the image_optimizer gem, particularly focusing on file upload features.
- Implement strict input validation and sanitization for any filenames or paths passed to backend image processing utilities to prevent shell metacharacter injection.
- Deploy runtime application self-protection (RASP) or static analysis tools to monitor for suspicious command execution originating from the application layer.
