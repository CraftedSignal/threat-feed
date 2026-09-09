---
title: Local File Inclusion in MaxSite CMS via Ajax Dispatchers
slug: 2026-09-maxsite-lfi
description: MaxSite CMS versions up to 109.6 contain a local file inclusion vulnerability in its ajax and require-maxsite dispatchers allowing unauthenticated attackers to execute arbitrary privileged handlers.
date: "2026-09-09T19:02:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:maxsite:maxsite_cms:*:*:*:*:*:*:*:*
tags:
  - web-application
  - lfi
  - vulnerability
vendors:
  - MaxSite
products:
  - MaxSite CMS (<= 109.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: MaxSite CMS through 109.6 contains a local file inclusion vulnerability in the ajax and require-maxs... dispatchers that allows unauthenticated attackers to execute privileged handler files.
    confidence_band: high
cves:
  - id: CVE-2026-87927
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87927
rules:
  - title: Detects CVE-2026-87927 Exploitation - LFI via Ajax Dispatcher
    description: Detects potential LFI attempts by identifying base64-encoded path traversal sequences in ajax or require-maxsite dispatching endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1210
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch MaxSite CMS to version > 109.6
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-87927 advisory
  hunt_leads:
    - lead: Search web logs for base64 strings in parameters to ajax or require-maxsite endpoints
      technique_id: T1210
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source description of attack vector via base64 traversal
  mitigation_plan:
    - priority: immediate
      action: WAF block of suspicious base64 encoded path traversal in CMS dispatchers
      owner: SOC
      addresses: CVE-2026-87927
      evidence: Source documentation of LFI via dispatchers
---

MaxSite CMS versions up to and including 109.6 are affected by a critical local file inclusion (LFI) vulnerability residing within the system's ajax and require-maxsite dispatchers. This flaw allows unauthenticated, remote attackers to bypass existing path validation mechanisms by supplying base64-encoded path traversal sequences. By successfully manipulating these request parameters, an adversary can force the application to load and execute internal, privileged handler files. Because these handlers often contain administrative functionality, successful exploitation grants the attacker unauthorized access to sensitive application features or administrative actions that should remain gated behind proper authentication. Defenders should prioritize patching, as this vulnerability provides a direct pathway for unauthenticated remote code execution or privilege escalation depending on the target handler logic.

## Impact

Successful exploitation of CVE-2026-87927 allows unauthenticated attackers to bypass security boundaries and execute privileged administrative functions within the MaxSite CMS environment. This can lead to full administrative takeover, unauthorized access to sensitive data, and potential remote code execution by leveraging internal handler scripts.

## Recommendation

- Upgrade MaxSite CMS to a version beyond 109.6 immediately as soon as a security patch is provided by the vendor.
- Implement strict input validation on all ajax and require-maxsite endpoints to detect and reject base64-encoded strings or character sequences indicative of path traversal (e.g., ../, ..\).
- Deploy WAF rules to identify and block incoming HTTP requests containing base64-encoded strings in parameters targeting the /ajax/ or /require-maxsite/ URI paths.
