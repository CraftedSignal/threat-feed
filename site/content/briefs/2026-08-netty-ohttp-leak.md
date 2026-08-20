---
title: Native Memory Leak in netty-incubator-codec-ohttp via CVE-2026-54251
slug: 2026-08-netty-ohttp-leak
description: The netty-incubator-codec-ohttp library suffers from a native memory leak during AEAD decryption failures, allowing unauthenticated attackers to induce a denial-of-service by exhausting off-heap memory.
date: "2026-08-20T19:13:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Netty
products:
  - netty-incubator-codec-ohttp
references:
  - https://github.com/advisories/GHSA-vmr9-j6wf-pmh2
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54251
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade netty-incubator-codec-ohttp to version 0.0.23.Final
      owner: IT Operations
      due: 48h
      evidence: Source advisory confirms patch availability in 0.0.23.Final
  mitigation_plan:
    - priority: immediate
      action: Rate limit OHTTP gateway endpoints
      owner: Security Engineering
      addresses: CVE-2026-54251
      evidence: Rate limiting reduces the speed of native memory exhaustion
---

The netty-incubator-codec-ohttp library is susceptible to a native memory leak (CVE-2026-54251) impacting versions prior to 0.0.23.Final. This vulnerability exists within the OHTTP gateway functionality, which leverages Netty's pooled direct memory management for handling encrypted requests. When the gateway receives an OHTTP request, it allocates a native off-heap 'ByteBuf' to store decrypted plaintext prior to verifying the AEAD authentication tag. If the AEAD tag verification fails due to malformed or malicious ciphertext, a 'CryptoException' is triggered; however, the library fails to include a 'try-finally' block to release the allocated buffer. Repeatedly sending requests with invalid AEAD tags forces the application to leak native memory with every failed attempt, eventually leading to exhaustion of the Java process's off-heap memory and a service-wide denial-of-service condition.

## Impact

Successful exploitation results in an application-level denial-of-service. By repeatedly triggering the memory leak, an attacker can exhaust the target system's native memory, causing the JVM process to crash or become unresponsive to legitimate OHTTP traffic. This vulnerability is particularly critical for high-traffic OHTTP gateways exposed to the internet.

## Recommendation

- Upgrade the 'netty-incubator-codec-ohttp' dependency to version 0.0.23.Final or higher immediately.
- Audit existing deployments for high memory utilization or 'OutOfMemoryError: Direct buffer memory' exceptions correlated with AEAD decryption errors.
- Implement rate limiting on OHTTP gateway endpoints to mitigate the frequency at which an attacker can trigger the vulnerable decryption path.
