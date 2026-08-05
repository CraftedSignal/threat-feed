---
title: Authentication Bypass and RCE Vulnerabilities in Milvus
slug: 2026-08-milvus-auth-bypass
description: Milvus vector database versions prior to 2.5.27 and 2.6.10 are vulnerable to multiple authentication bypass flaws and arbitrary expression execution, allowing attackers to gain full administrative access.
date: "2026-08-05T06:08:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:milvus:milvus:*:*:*:*:*:*:*:*
tags:
  - milvus
  - authentication-bypass
  - remote-code-execution
  - cve-2025-64513
  - cve-2026-26190
vendors:
  - Milvus
products:
  - Milvus (2.5.x)
  - Milvus (2.6.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The entry point allows arbitrary expression evaluation and authentication bypass.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The sourceId backdoor allows an attacker to masquerade as root and gain administrative access.
    confidence_band: high
cves:
  - id: CVE-2025-64513
    epss: 0.0107
  - id: CVE-2026-26190
    cvss: 9.8
    epss: 0.36912
references:
  - https://sploitus.com/exploit?id=CCE27BEF-74DE-5AC7-8FA0-F4D0E1A5839B
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade all Milvus instances to version 2.6.10
      owner: IT Operations
      due: 24h
      evidence: CVE-2025-64513 and CVE-2026-26190 are resolved in version 2.6.10.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to management port 9091 and internal port 53100
      owner: IT Operations
      addresses: CVE-2026-26190
      evidence: Source material indicates internal port 53100 should not be exposed to external traffic.
---

Milvus is susceptible to critical authentication vulnerabilities that permit unauthenticated remote attackers to bypass security controls and gain administrative access. The most notable issue, CVE-2025-64513, involves a hardcoded 'sourceId' header ('@@milvus-member@@') used in the `validSourceID()` function within `internal/proxy/authentication_interceptor.go`. This header forces the proxy to skip authentication entirely, allowing an attacker to forge an identity and gain administrative privileges by providing a base64-encoded 'root' credential.

Furthermore, CVE-2026-26190 affects two other components: the `/expr` debug endpoint on management port 9091, which utilizes a weak, predictable default authentication token ('by-dev'), and the lack of authentication on the internal gRPC port 53100. These flaws allow arbitrary expression execution and unauthorized database access. While newer versions (2.6.10+) mitigate these by disabling the `/expr` endpoint by default and closing internal port 53100, existing unpatched instances remain at high risk.

## Attack Chain

1. Attacker performs network reconnaissance to identify exposed Milvus management (9091) or proxy (19530) ports.
2. Attacker crafts a gRPC request or HTTP request targeting the proxy port (19530).
3. Attacker injects the 'sourceId' header with the value '@@milvus-member@@' to trigger the authentication interceptor bypass (CVE-2025-64513).
4. Attacker provides authorization credentials formatted as base64 'root:fake_password' to masquerade as an administrator.
5. Attacker gains full administrative access to the Milvus proxy.
6. Alternatively, the attacker targets port 9091 and authenticates to the /expr endpoint using the default token 'by-dev' (CVE-2026-26190).
7. Attacker submits malicious 'expr-lang' expressions through the /expr endpoint to achieve arbitrary code execution.
8. Attacker executes database queries or administrative commands to exfiltrate or manipulate stored vector data.

## Impact

Successful exploitation grants an attacker full administrative control over the Milvus database instance. This impact includes the potential for total data exfiltration, database manipulation, and further compromise of the underlying infrastructure hosting the Milvus service. As a vector database, Milvus often stores critical AI/ML embeddings and intellectual property, making it a high-value target for threat actors.

## Recommendation

- Upgrade all Milvus deployments to version 2.6.10 or later immediately to patch CVE-2025-64513 and CVE-2026-26190.
- Implement network-level access control lists (ACLs) to restrict access to ports 19530, 9091, and 53100 to known trusted internal IP addresses only.
- Monitor logs for unusual authentication headers or high-frequency requests to the /expr debug endpoint.
- If upgrading is not immediately possible, explicitly disable the /expr endpoint by setting `common.security.exprEnabled` to `false` in the Milvus configuration.
