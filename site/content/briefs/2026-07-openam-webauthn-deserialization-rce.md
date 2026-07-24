---
title: Critical Unauthenticated Remote Code Execution in OpenAM WebAuthn due to Deserialization Vulnerability (CVE-2026-62263)
slug: 2026-07-openam-webauthn-deserialization-rce
description: A critical remote code execution (RCE) vulnerability, CVE-2026-62263, exists in OpenAM's WebAuthn authenticator deserialization, allowing an unauthenticated attacker to bypass an `ObjectInputFilter` and execute arbitrary code by crafting a malicious serialized stream before authentication.
date: "2026-07-24T21:10:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - deserialization
  - rce
  - webauthn
  - java
  - openam
  - vulnerability
vendors:
  - OpenIdentityPlatform
products:
  - openam-auth-webauthn
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can craft a stream rooted at `AuthenticatorImpl` with an arbitrary gadget chain nested inside. The gadget's `readObject`/`readResolve` executes during `readObject()` — before the cast and before any assertion verification — enabling remote code execution when a gadget is on the classpath. The deserialization sink is reached pre-authentication via an attacker-chosen `userHandle`.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: enabling remote code execution when a gadget is on the classpath. The deserialization sink is reached pre-authentication via an attacker-chosen `userHandle`.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-gf8h-gq53-288j
---

A critical deserialization vulnerability, tracked as CVE-2026-62263, has been identified in the `openam-auth-webauthn` component of OpenAM (Open Identity Platform). This flaw affects versions up to and including 16.1.1. The vulnerability stems from an insufficient fix (GHSA-6c99-87fr-6q7r) that attempted to secure WebAuthn authenticator deserialization using an `ObjectInputFilter`. However, the filter is inadvertently bypassed for any object at a stream depth greater than one, effectively constraining only the root object and leaving nested serialized objects unchecked. This design flaw allows an unauthenticated attacker to craft a specially designed serialized stream containing arbitrary Java gadget chains. When processed by OpenAM, this stream can trigger remote code execution (RCE) before any authentication takes place, posing a severe risk to affected deployments.

## Attack Chain

1. An unauthenticated attacker prepares a malicious serialized Java object stream.
2. The attacker crafts the root of this stream to be an `AuthenticatorImpl` object.
3. Nested within the `AuthenticatorImpl` object, the attacker embeds a malicious gadget chain.
4. The attacker sends this crafted serialized stream to the OpenAM server via an attacker-chosen `userHandle`, targeting the WebAuthn deserialization sink.
5. OpenAM attempts to deserialize the incoming WebAuthn authenticator data.
6. During deserialization, the `ObjectInputFilter` is consulted but mistakenly short-circuits to `ALLOWED` for objects at a stream depth greater than one.
7. The embedded gadget chain's `readObject()` or `readResolve()` methods are invoked, leading to the execution of arbitrary code on the server.
8. The attacker achieves unauthenticated remote code execution on the OpenAM server, gaining control of the system.

## Impact

Successful exploitation of CVE-2026-62263 grants unauthenticated remote code execution (RCE) on the OpenAM server. This allows attackers to completely compromise the integrity, confidentiality, and availability of the affected system. Attackers could install backdoors, exfiltrate sensitive user authentication data, disrupt identity services, or pivot to other systems within the compromised network. The vulnerability affects `maven/org.openidentityplatform.openam:openam-auth-webauthn` in all versions up to and including 16.1.1, making a wide range of OpenAM deployments susceptible to this critical flaw.

## Recommendation

* Patch CVE-2026-62263 by upgrading `maven/org.openidentityplatform.openam:openam-auth-webauthn` to a version greater than 16.1.1 immediately.
* Review web server logs for the OpenAM application for suspicious requests that involve unusually large or malformed `userHandle` parameters.
