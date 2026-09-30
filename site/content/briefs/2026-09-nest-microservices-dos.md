---
title: Remote Denial of Service in NestJS Microservices via Deeply Nested Patterns
slug: 2026-09-nest-microservices-dos
description: An unhandled stack overflow exception in @nestjs/microservices, triggered by deeply nested JSON message patterns, allows unauthenticated remote attackers to crash Node.js processes using TCP or RabbitMQ transports.
date: "2026-09-30T04:18:57Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:nestjs:microservices:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - npm
  - nestjs
vendors:
  - NestJS
products:
  - '@nestjs/microservices (>= 12.0.0 < 12.0.2)'
  - '@nestjs/microservices (< 11.2.4)'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A single message whose pattern is a deeply nested object terminates a NestJS microservice that uses the TCP or RabbitMQ transport.
    confidence_band: high
cves:
  - id: CVE-2026-102281
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-m8vh-jmq9-5rjg
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade @nestjs/microservices to v11.2.4 or v12.0.2 to remediate CVE-2026-102281.
      owner: Application Security
      due: 24h
      evidence: Fixed in 12.0.2 and 11.2.4.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to transport ports (e.g. TCP 3001) to known authorized peers.
      owner: Network Security
      addresses: CVE-2026-102281
      evidence: If you cannot upgrade, restrict network access to the transport so that only trusted peers can reach it.
---

NestJS microservices using the `@nestjs/microservices` package are vulnerable to a remote denial-of-service (DoS) attack (CVE-2026-102281). The vulnerability exists within the TCP and RabbitMQ transport handlers, where the library attempts to serialize a client-supplied 'pattern' using `JSON.stringify` to generate a handler lookup key. An attacker can supply a specially crafted, deeply nested JSON object that is syntactically valid but causes `JSON.stringify` to exceed the call stack limit. This results in a `RangeError: Maximum call stack size exceeded`. Because the transport handlers do not implement adequate rejection handling for these asynchronous operations, the error propagates as an unhandled promise rejection, causing the Node.js process to terminate immediately. This exploit is repeatable and requires only network access to the transport layer, which is often unauthenticated by default for the TCP transport.

## Attack Chain

1. Attacker identifies an exposed NestJS microservice utilizing the TCP transport on its default port (e.g., 3001) or a RabbitMQ consumer endpoint.
2. Attacker crafts a malicious payload containing a deeply nested JSON object within the 'pattern' field, exceeding standard recursion depths.
3. Attacker sends the payload to the target microservice via the transport layer (e.g., raw TCP frame or RabbitMQ message).
4. The microservice receives the payload and passes the 'pattern' object to the `JSON.stringify` function inside the transport message handler.
5. `JSON.stringify` attempts to serialize the deeply nested structure, triggering a `RangeError: Maximum call stack size exceeded`.
6. The error manifests as an unhandled promise rejection within the transport handler.
7. The Node.js process environment (default `--unhandled-rejections=throw`) terminates the process, resulting in a successful denial-of-service.

## Impact

The attack results in a repeatable denial-of-service, rendering the microservice unresponsive by crashing the host process. The impact is significant for applications relying on microservices for core business logic, as a single crafted message can halt service availability. The vulnerability affects all NestJS services using the TCP or RabbitMQ transports that have not been patched to versions 11.2.4 or 12.0.2 respectively.

## Recommendation

Prioritized actions for detection and remediation:
- Upgrade `@nestjs/microservices` to version 11.2.4 or 12.0.2 immediately to implement the required input guards and improved error handling.
- Patch CVE-2026-102281 by deploying the updated dependencies across all internet-facing or internal microservices.
- Restrict network access to transport ports (TCP 3001 or RabbitMQ management/consumption ports) to authorized internal IP addresses only.
- Implement infrastructure-level rate limiting and payload validation to block abnormally deeply nested JSON objects before they reach the application tier.
