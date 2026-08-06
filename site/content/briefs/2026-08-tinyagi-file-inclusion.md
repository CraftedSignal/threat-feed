---
title: Remote File Inclusion Vulnerability in TinyAGI
slug: 2026-08-tinyagi-file-inclusion
description: TinyAGI version 0.0.20 contains a remote file inclusion vulnerability in the Message API Endpoint, which allows unauthenticated attackers to access arbitrary files on the system.
date: "2026-08-06T09:22:41Z"
lastmod: "2026-08-06T09:22:49Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - TinyAGI (0.0.20)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely, and the exploit has been made available to the public and could be used for attacks.
    confidence_band: high
cves:
  - id: CVE-2026-19009
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19009
  - https://github.com/TinyAGI/tinyagi/issues/282
  - https://vuldb.com/vuln/386402
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19010
  - https://github.com/TinyAGI/tinyagi/issues/284
rules:
  - title: Detect CVE-2026-19009 Exploitation - Path Traversal in Message API
    description: Detects potential attempts to exploit CVE-2026-19009 by monitoring for path traversal patterns in requests to the TinyAGI Message API.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory instances of TinyAGI 0.0.20 and restrict access to the Message API endpoint via WAF.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-19009 affects TinyAGI 0.0.20 and is remotely exploitable.
  hunt_leads:
    - lead: Search logs for HTTP requests to /Message/ endpoints containing path traversal characters.
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: CVE-2026-19009 involves path manipulation via the collectFiles function.
updates:
  - at: "2026-08-06T09:22:49Z"
    level: L2
    summary: added coverage for TinyAGI (0.0.20)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19010
---

A remote file inclusion vulnerability has been identified in TinyAGI version 0.0.20, specifically within the `collectFiles` function of the `packages/core/src/response.ts` file. This component is part of the Message API Endpoint. The flaw, tracked as CVE-2026-19009, stems from improper validation of external inputs, which allows a remote, unauthenticated attacker to manipulate file paths and trigger file inclusion. This vulnerability is classified as CWE-73: External Control of File Name or Path. Publicly available exploit code exists, and the project maintainers have not yet provided a response or a patch as of the initial disclosure. Defenders should prioritize identifying instances of TinyAGI 0.0.20 in their environments and restrict network access to the affected Message API endpoint.

## Attack Chain

1. Attacker performs reconnaissance to identify public-facing instances of the TinyAGI Message API endpoint.
2. Attacker interacts with the vulnerable `collectFiles` function via HTTP requests directed at the Message API endpoint.
3. Attacker crafts a malicious request containing a manipulated file path or URI parameter that bypasses intended path validation.
4. The `collectFiles` function processes the malicious input and improperly resolves the path, leading to file inclusion.
5. The application reads or includes the content of a sensitive file from the host filesystem based on the attacker's input.
6. The application returns the contents of the targeted file within the HTTP response, resulting in unauthorized information disclosure.
7. Attacker potentially uses the recovered information (e.g., credentials or configuration files) to escalate access or conduct further exploitation.

## Impact

Successful exploitation of CVE-2026-19009 allows an unauthenticated remote attacker to read arbitrary files from the filesystem of the server hosting TinyAGI. This can lead to the exposure of sensitive configuration data, environment variables, source code, or internal credentials, significantly compromising the confidentiality of the affected system. The existence of public exploit code increases the likelihood of opportunistic attacks targeting this vulnerability.

## Recommendation

* Identify and inventory all instances of TinyAGI version 0.0.20 within the corporate environment.
* Restrict external access to the TinyAGI Message API endpoint using a Web Application Firewall (WAF) or network access control list (ACL) until a security patch is developed.
* Implement rigorous input validation on all API endpoints that accept file paths or URI parameters.
* Monitor web server logs for suspicious HTTP requests targeting the Message API endpoint containing path traversal sequences like '../' or attempts to access common system configuration files.
