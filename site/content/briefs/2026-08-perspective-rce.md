---
title: Unauthenticated Remote Code Execution in Perspective 5.0.0
slug: 2026-08-perspective-rce
description: Perspective version 5.0.0 is vulnerable to unauthenticated remote code execution via unsafe Python eval() calls within the PolarsVirtualServer backend triggered by crafted protobuf messages.
date: "2026-08-04T15:44:15Z"
lastmod: "2026-08-04T15:44:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - cve-2026-67195
  - perspective
  - denial-of-service
  - vulnerability
  - CVE-2026-67198
vendors:
  - Perspective
products:
  - Perspective (5.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Perspective 5.0.0 contains a remote code execution vulnerability that allows unauthenticated attackers to execute arbitrary operating system commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.006
    technique_name: 'Command and Scripting Interpreter: Python'
    evidence: The PolarsVirtualServer backend passes client-supplied input directly to Python's eval() with only __builtins__={} cleared.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Perspective 5.0.0 contains a denial-of-service vulnerability in the VirtualServer protocol dispatcher that allows unauthenticated remote attackers to crash the server process.
    confidence_band: high
cves:
  - id: CVE-2026-67195
    cvss: 8.8
  - id: CVE-2026-67200
    cvss: 7.5
  - id: CVE-2026-67198
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67195
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67198
  - https://www.vulncheck.com/advisories/perspective-dos-via-virtualserver-protocol-dispatcher
  - https://christbowel.com/blog/perspective-5-0-0-five-cves/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67200
updates:
  - at: "2026-08-04T15:44:24Z"
    level: L1
    summary: 'merged source coverage: Denial-of-Service Vulnerability in Perspective VirtualServer'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-67198
  - at: "2026-08-04T15:44:26Z"
    level: L2
    summary: added CVE-2026-67198 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-67200
---

Perspective version 5.0.0 contains a critical remote code execution vulnerability (CVE-2026-67195) located within its PolarsVirtualServer backend component. The vulnerability originates from the unsafe handling of client-supplied expression strings, which are passed directly to Python's eval() function. Although the application attempts to restrict the environment by clearing __builtins__, this mechanism is insufficient as it does not prevent object attribute traversal. An attacker can leverage this limitation to traverse the interpreter's loaded class hierarchy, eventually accessing subprocess.Popen to execute arbitrary operating system commands. This flaw is reachable by unauthenticated attackers who can deliver specially crafted TableValidateExprReq or TableMakeViewReq protobuf messages to the service. Given that Perspective is often deployed in data-intensive environments, successful exploitation allows an attacker to gain full control over the host process and the underlying system.

## Impact

Successful exploitation of this vulnerability results in unauthenticated remote code execution with the privileges of the Perspective host process. This can lead to full system compromise, data exfiltration, or the deployment of further post-exploitation payloads. All instances of Perspective 5.0.0 are considered high-risk until patched.

## Recommendation

- Identify all deployments of Perspective 5.0.0 in the environment and verify if they are internet-facing.
- Implement network-level access controls to restrict access to the PolarsVirtualServer service to trusted management segments only.
- Prioritize upgrading Perspective to a patched version once provided by the vendor.
- Monitor server logs for incoming traffic containing protobuf serialization patterns associated with TableValidateExprReq or TableMakeViewReq types if application-level inspection is available.
