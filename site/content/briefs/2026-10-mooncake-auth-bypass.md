---
title: Authentication Bypass in Mooncake Metadata Server
slug: 2026-10-mooncake-auth-bypass
description: Mooncake versions through 0.3.13.post1 contain an authentication bypass in the HTTP metadata server, allowing unauthenticated attackers to manipulate transfer engine keys, redirect data, or trigger denial-of-service.
date: "2026-10-02T00:19:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:mooncake:mooncake:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - cve-2026-103765
vendors:
  - Mooncake
products:
  - Mooncake (<= 0.3.13.post1)
cves:
  - id: CVE-2026-103765
    cvss: 9.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103765
rules:
  - title: Detect Unauthorized Access to Mooncake Metadata Handler
    description: Detects unauthenticated access attempts to the Mooncake metadata server /metadata endpoint using modification methods.
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
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Restrict network access to the Mooncake metadata server port
      owner: IT Operations
      due: 24h
      evidence: Source confirms authentication is missing on the HTTP metadata server
  mitigation_plan:
    - priority: immediate
      action: Upgrade Mooncake to a patched version beyond 0.3.13.post1
      owner: IT Operations
      addresses: CVE-2026-103765
      evidence: NVD vulnerability entry documenting the vulnerability in versions through 0.3.13.post1
---

Mooncake through version 0.3.13.post1 contains a critical missing authentication vulnerability in its HTTP metadata server, specifically within the /metadata handler. This vulnerability allows an unauthenticated, remote attacker to perform unauthorized read, overwrite, and delete operations on sensitive transfer engine metadata keys. 

The flaw is significant because it allows attackers to poison segment descriptors, such as the 'tcp_data_port' key, or re-create 'rpc_meta' entries. By manipulating these metadata keys, an attacker can effectively redirect KV cache transfers to attacker-controlled listeners, leading to potential data interception. Furthermore, the ability to overwrite or delete metadata keys can be leveraged to exhaust server memory, resulting in a denial-of-service condition. Given the nature of the application, this flaw poses a high risk to data integrity and availability for deployments utilizing the Mooncake transfer engine.

## Impact

Successful exploitation allows unauthenticated attackers to intercept data transfers by redirecting KV cache traffic or crash the service by exhausting system memory. The vulnerability affects all Mooncake deployments using versions up to 0.3.13.post1.

## Recommendation

1. Upgrade to the latest version of Mooncake (beyond 0.3.13.post1) immediately upon the vendor release of a security patch.
2. Implement network-level access controls to restrict access to the Mooncake HTTP metadata server port to trusted administrative subnets only.
3. Monitor webserver logs for unauthorized HTTP requests to the /metadata endpoint, specifically those utilizing PUT, POST, or DELETE methods from unexpected IP addresses.
