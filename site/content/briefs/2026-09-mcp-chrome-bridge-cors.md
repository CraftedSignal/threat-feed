---
title: Origin Validation Error in mcp-chrome-bridge native-server HTTP API
slug: 2026-09-mcp-chrome-bridge-cors
description: An origin validation vulnerability in mcp-chrome-bridge versions 1.0.31 and earlier allows attackers to bypass CORS and perform unauthorized browser automation actions via malicious web pages.
date: "2026-09-29T20:30:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mcp-chrome-bridge:mcp-chrome-bridge:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - browser-security
  - cors-bypass
  - mcp-chrome-bridge
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can craft malicious web pages that make cross-origin requests to the local server.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Invoke browser automation tools including script execution.
    confidence_band: high
cves:
  - id: CVE-2026-102878
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102878
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update all instances of mcp-chrome-bridge beyond version 1.0.31
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-102878 vulnerability report
  mitigation_plan:
    - priority: immediate
      action: Review local firewall rules for browser automation tools
      owner: Security Operations
      addresses: CVE-2026-102878
      evidence: Origin validation error in native-server HTTP API
---

mcp-chrome-bridge versions up to 1.0.31 contain an origin validation error within the native-server HTTP API. This vulnerability allows an attacker to bypass Cross-Origin Resource Sharing (CORS) restrictions. By hosting a malicious website, an attacker can trick a user's browser into making unauthorized cross-origin requests to the local server process running as part of the bridge application. This flaw enables an attacker to invoke browser automation tools directly, which can result in arbitrary script execution, reading sensitive page content from the browser, or capturing unauthorized screenshots of the user's active browser sessions. This is particularly dangerous for developers who use these tools for local automation, as the bridge inherently has high-privilege access to browser interfaces.

## Impact

Successful exploitation allows remote attackers to execute code in the context of the user's browser or exfiltrate sensitive data from open browser tabs. This threatens developers and automated testing environments using mcp-chrome-bridge, as it provides a mechanism for local information theft and persistent browser-based execution via a browser-borne attack vector.

## Recommendation

* Update mcp-chrome-bridge to the latest available version beyond 1.0.31 to patch the origin validation logic.
* Restrict access to the native-server HTTP API to trusted local origin domains only.
* Monitor for unauthorized cross-origin traffic initiated from browser-based applications to local server ports where mcp-chrome-bridge may be listening.
