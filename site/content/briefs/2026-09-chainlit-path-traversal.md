---
title: Path Traversal and Arbitrary Deletion in Chainlit
slug: 2026-09-chainlit-path-traversal
description: Chainlit versions 2.12.0 and earlier are vulnerable to an unauthenticated path traversal attack via the socket.io sessionId parameter, enabling arbitrary directory deletion.
date: "2026-09-09T14:58:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:chainlit:chainlit:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - path-traversal
  - arbitrary-deletion
vendors:
  - Chainlit
products:
  - Chainlit (<= 2.12.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can exploit this flaw by supplying specially crafted path sequences to escape the intended upload directory.
    confidence_band: high
cves:
  - id: CVE-2026-86099
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86099
rules:
  - title: Detect CVE-2026-86099 Path Traversal Attempt
    description: Detects potential path traversal attempts in socket.io session ID parameters targeting Chainlit
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
    - action: Patch Chainlit to version > 2.12.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-86099 affects versions through 2.12.0
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to block path traversal sequences in URI parameters
      owner: SOC
      addresses: CVE-2026-86099
      evidence: Path traversal via sessionId parameter
---

Chainlit versions up to and including 2.12.0 contain a critical path traversal vulnerability (CVE-2026-86099) originating from the improper validation of the client-supplied `sessionId` parameter within `socket.io` communications. An unauthenticated attacker can exploit this flaw by submitting crafted `sessionId` values containing path traversal sequences, such as dot-dot-slash patterns. This manipulation allows the attacker to break out of the application-defined upload directory. Once the escape is successful, the attacker can target sensitive files or directories, ultimately triggering recursive deletion of any path accessible to the service process. The impact is significant, as it enables destructive actions against the underlying filesystem without requiring prior authentication. Given the nature of the vulnerability, defenders should prioritize patching and monitoring for anomalous `socket.io` traffic targeting the session identifier.

## Impact

Successful exploitation allows unauthenticated attackers to delete arbitrary directories on the host server. This can lead to total service disruption, data loss, or the deletion of critical system or application components, depending on the service account's permissions.

## Recommendation

* Patch Chainlit to a version newer than 2.12.0 as soon as a fix is made available by the vendor.
* Monitor web server logs for socket.io traffic containing unconventional characters in the `sessionId` parameter, specifically path traversal sequences like `../` or `..\\`.
* Ensure the Chainlit service process is running with the principle of least privilege, restricting its write and delete permissions to only the necessary directories.
