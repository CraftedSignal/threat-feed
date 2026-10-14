---
title: Heap Buffer Overflow in NGINX
slug: 2026-10-nginx-heap-overflow
description: CVE-2026-15176 is a heap buffer overflow vulnerability in NGINX Plus and NGINX Open Source that allows remote unauthenticated attackers to cause a denial of service or potentially execute arbitrary code by sending crafted HTTP requests.
date: "2026-10-14T16:38:22Z"
lastmod: "2026-10-14T16:40:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:nginx_plus:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - dos
  - remote-code-execution
  - cve
vendors:
  - F5
products:
  - NGINX Plus
  - NGINX Open Source
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Successful exploitation can lead to a worker process crash (DoS), memory corruption, or remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.
    confidence_band: high
cves:
  - id: CVE-2026-15176
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15176
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97205
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Audit NGINX configuration files for vulnerable directives
      owner: Security Engineering
      due: 48h
      evidence: Source document identifies specific directive combinations as the trigger
  mitigation_plan:
    - priority: immediate
      action: Remove $request_filename from access log format directives
      owner: IT Operations
      addresses: CVE-2026-15176
      evidence: Source identifies access log usage as a viable trigger for the overflow
  gaps:
    - Lack of specific vendor patch version in source document
updates:
  - at: "2026-10-14T16:40:37Z"
    level: L2
    summary: added coverage for NGINX Plus +1 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-97205
---

CVE-2026-15176 is a heap buffer overflow vulnerability affecting NGINX Plus and NGINX Open Source. The vulnerability arises when specific configuration directives are combined within an NGINX location block: the alias directive used in conjunction with a rewrite directive, or a set or return directive that references the $request_filename variable. Additionally, the vulnerability can be triggered if the $request_filename variable is included in an access log format directive. 

An unauthenticated remote attacker can exploit this flaw by sending crafted HTTP requests that trigger the buffer overflow within the NGINX worker process. While the primary documented impact is a denial-of-service condition resulting from worker process restarts, the memory corruption potentially allows for arbitrary code execution in environments where Address Space Layout Randomization (ASLR) is disabled or successfully bypassed. This is a data plane vulnerability and does not affect the NGINX control plane.

## Impact

Successful exploitation of CVE-2026-15176 leads to worker process crashes, causing intermittent or persistent denial-of-service conditions for the affected web service. In sophisticated scenarios, the heap overflow primitive may enable remote code execution, threatening the confidentiality, integrity, and availability of the host server. The vulnerability impacts all NGINX Open Source and NGINX Plus installations utilizing the vulnerable directive combinations, posing a significant risk to internet-facing web infrastructure.

## Recommendation

Prioritize auditing NGINX configuration files to identify the use of the alias directive in combination with rewrite, set, or return directives that reference $request_filename.

* Review all custom 'log_format' configurations to ensure the $request_filename variable is not utilized in production access logs until a vendor patch is applied.
* Monitor NGINX error logs for unexpected worker process crashes or segmentation faults, which may indicate exploitation attempts.
* Apply patches provided by F5 for NGINX Plus and NGINX Open Source as soon as they become available for your specific deployment version.
* Ensure Address Space Layout Randomization (ASLR) is enabled and enforced at the operating system level for all NGINX host environments to increase the cost of exploitation.
