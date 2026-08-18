---
title: Arbitrary Class Loading in RabbitMQ Java Client via JSON-RPC
slug: 2026-08-rabbitmq-rce
description: The RabbitMQ Java client library is vulnerable to arbitrary class loading and static initializer execution via unvalidated input in the JSON-RPC ProcedureDescription, which can lead to remote code execution.
date: "2026-08-18T20:58:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - java
  - rce
  - rabbitmq
  - cve-2026-63337
vendors:
  - RabbitMQ
products:
  - amqp-client
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The library uses Class.forName on class names received from untrusted AMQP messages without validation... causing the victim's client to load the specified class and execute its static initializers.
    confidence_band: high
cves:
  - id: CVE-2026-63337
references:
  - https://github.com/advisories/GHSA-6g32-pxv4-2wfj
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade amqp-client to version 5.33.0 across all Java applications.
      owner: IT Operations
      due: 48h
      evidence: 'Affected Packages: maven/com.rabbitmq:amqp-client (vulnerable: < 5.33.0)'
  mitigation_plan:
    - priority: immediate
      action: Patch CVE-2026-63337 by updating dependencies.
      owner: IT Operations
      addresses: CVE-2026-63337
      evidence: Source advisory recommends upgrading to 5.33.0
---

The RabbitMQ Java client (amqp-client), specifically the `com.rabbitmq.tools.jsonrpc` component, is susceptible to an arbitrary class loading vulnerability tracked as CVE-2026-63337. The vulnerability exists due to the use of `Class.forName()` on class names provided within the `javaReturnType` field of JSON-RPC `system.describe` responses received via AMQP. The client fails to implement an allowlist or validation for these class names, and performs the lookup with the `initialize=true` flag.

An attacker who can influence the response to a `system.describe` call, such as through a compromised or malicious broker, can force the client to load arbitrary classes present on the classpath. Because the `initialize` parameter is set to true, any static initializers defined within those classes are executed immediately upon loading. This flaw facilitates potential remote code execution (RCE) in the context of the victim's application, in addition to potential type-confusion attacks during subsequent data parsing.

## Attack Chain

1. The victim application initializes a `JsonRpcClient` to interact with a JSON-RPC service over a RabbitMQ broker.
2. The client sends a `system.describe` request via the AMQP queue.
3. The attacker intercepts the communication or acts as a malicious broker and provides a crafted JSON response.
4. The attacker sets the `javaReturnType` field in the JSON response to a target malicious or sensitive class name present in the application's classpath.
5. The `JsonRpcClient` receives the response and processes the `javaReturnType` field via `JSONUtil.fill()`.
6. The `computeReturnTypeAsJavaClass()` method is invoked, triggering `Class.forName()` with the attacker-supplied class name and `initialize=true`.
7. The JVM loads the specified class and triggers its static initializer block.
8. Arbitrary code defined in the static initializer executes within the victim's process, achieving RCE or other local impact.

## Impact

The vulnerability allows for arbitrary class loading and static initializer execution, which poses a significant risk of remote code execution for any application utilizing the `com.rabbitmq.tools.jsonrpc` package. Affected versions include all versions of the RabbitMQ Java client prior to 5.33.0. Successful exploitation requires an attacker to be positioned as a broker or intercepting party between the client and the JSON-RPC endpoint.

## Recommendation

Prioritized actions for addressing CVE-2026-63337:

- Upgrade the RabbitMQ Java client (amqp-client) to version 5.33.0 or later immediately to patch the insecure `Class.forName` calls.
- Review applications using `com.rabbitmq.tools.jsonrpc` for exposure to untrusted AMQP brokers.
- If immediate patching is not possible, implement an application-side filter to intercept and validate the `javaReturnType` string against an strict allowlist of expected classes before the library processes the JSON response.
