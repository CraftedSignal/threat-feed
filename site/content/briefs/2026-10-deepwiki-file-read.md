---
title: Unauthenticated Arbitrary File Read in DeepWiki-Open
slug: 2026-10-deepwiki-file-read
description: DeepWiki-Open through commit d92819a is vulnerable to an unauthenticated arbitrary file read via the repo_url parameter in the GET /codemap/file endpoint.
date: "2026-10-01T00:37:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:deepwiki-open:deepwiki-open:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - file-read
  - path-traversal
vendors:
  - DeepWiki-Open
products:
  - DeepWiki-Open (<= d92819a)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers can supply a non-URL repo_url value to bypass path containment checks and read any file accessible to the API process.
    confidence_band: high
cves:
  - id: CVE-2026-103591
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103591
rules:
  - title: Detect CVE-2026-103591 Exploitation - Arbitrary File Read
    description: Detects potential exploitation of CVE-2026-103591 by monitoring for absolute file paths or directory traversal patterns within the repo_url parameter of the /codemap/file endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade DeepWiki-Open beyond commit d92819a
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-103591 advisory
  hunt_leads:
    - lead: Search logs for unusual repo_url values in /codemap/file requests
      technique_id: T1083
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CVE-2026-103591 describes path traversal via repo_url
---

DeepWiki-Open through commit d92819a contains an unauthenticated arbitrary file read vulnerability. The issue resides in the GET /codemap/file endpoint, which improperly validates the repo_url parameter. By supplying a non-URL value, an attacker can bypass intended path containment checks. This allows for the traversal of the filesystem and the retrieval of sensitive files accessible to the API process. This vulnerability poses a significant risk as it requires no authentication to exploit and provides a mechanism for attackers to exfiltrate configuration files, source code, or system credentials. Defenders should prioritize patching or restricting access to the affected endpoint.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary files from the host system with the privileges of the web application process. This can lead to the exposure of sensitive credentials, environment variables, and internal configuration details, potentially facilitating further system compromise or data exfiltration.

## Recommendation

* Apply the official patch or upgrade DeepWiki-Open to a commit post-d92819a.
* Restrict network access to the /codemap/file endpoint using a Web Application Firewall or proxy server until the vulnerability is remediated.
* Monitor web server logs for GET requests to /codemap/file that contain filesystem path patterns or absolute paths in the repo_url query parameter.
