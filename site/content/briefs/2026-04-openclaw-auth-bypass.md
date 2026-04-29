---
title: OpenClaw Improper Authorization Vulnerability (CVE-2026-42426)
slug: 2026-04-openclaw-auth-bypass
description: OpenClaw before 2026.4.8 contains an improper authorization vulnerability (CVE-2026-42426) allowing attackers with `operator.write` permissions to bypass node pairing approval and gain unauthorized access to `exec`-capable nodes by exploiting the `node.pair.approve` method which incorrectly accepts the `operator.write` scope instead of the narrower `operator.pairing` scope.
date: "2026-04-28T19:37:46Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-42426
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42426
  - https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-67mf-f936-ppxf
  - https://www.vulncheck.com/advisories/openclaw-improper-authorization-in-node-pair-approve-via-operator-write-scope
rules:
  - title: Detect OpenClaw node.pair.approve Attempt with Operator.write Scope
    description: Detects attempts to call the node.pair.approve method in OpenClaw using accounts that only have operator.write permissions, indicating a potential CVE-2026-42426 exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw node.pair.approve Method Call
    description: Detects calls to the OpenClaw node.pair.approve method, which can be used to identify potential unauthorized pairing attempts. This rule does not specifically detect exploitation but provides broad visibility of the affected API.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.4.8 are vulnerable to an improper authorization flaw (CVE-2026-42426). The vulnerability resides within the `node.pair.approve` method, which erroneously accepts the `operator.write` scope instead of the intended `operator.pairing` scope. This oversight enables users possessing `operator.write` permissions, which are typically less privileged, to circumvent the intended node pairing approval process. Successful exploitation allows unauthorized access to nodes capable of executing commands (`exec`-capable nodes). This vulnerability was publicly disclosed in April 2026 and presents a significant risk to OpenClaw deployments, potentially leading to unauthorized command execution and data compromise.

## Attack Chain

1.  Attacker gains `operator.write` permissions, potentially through compromised credentials or other means.
2.  Attacker identifies an `exec`-capable node that requires pairing.
3.  Attacker crafts a request to the `node.pair.approve` method, using their `operator.write` credentials.
4.  The `node.pair.approve` method incorrectly validates the `operator.write` scope, instead of requiring `operator.pairing`.
5.  The node pairing request is approved despite the attacker lacking the proper `operator.pairing` permission.
6.  The attacker establishes a connection to the now-paired `exec`-capable node.
7.  Attacker executes arbitrary commands on the compromised node due to the unauthorized pairing.

## Impact

Successful exploitation of CVE-2026-42426 allows attackers with `operator.write` permissions to bypass node pairing restrictions and gain unauthorized access to `exec`-capable nodes. This can lead to arbitrary command execution on the affected nodes, potentially leading to data breaches, system compromise, or denial-of-service conditions. The severity of the impact depends on the capabilities and data accessible to the compromised node.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.8 or later to patch CVE-2026-42426.
*   Monitor OpenClaw logs for attempts to call the `node.pair.approve` method using accounts with only `operator.write` permissions. Deploy the Sigma rule to detect this activity.
*   Review and enforce strict access control policies to minimize the risk of unauthorized users obtaining `operator.write` permissions.
