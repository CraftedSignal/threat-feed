---
title: Information Exposure of HPKE Private Keys in Netty Incubator
slug: 2026-08-netty-hpke-exposure
description: The netty-incubator-codec-ohttp-hpke-classes-boringssl library exposes raw HPKE private key bytes in its toString() methods and exception messages, potentially leading to hardcoded key material in application logs.
date: "2026-08-20T19:12:50Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Netty
products:
  - netty-incubator-codec-ohttp-hpke-classes-boringssl
references:
  - https://github.com/advisories/GHSA-2mc4-j865-9q4r
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61798
---

The library `netty-incubator-codec-ohttp-hpke-classes-boringssl` (up to and including version 0.0.22.Final) contains a critical information exposure vulnerability related to the handling of HPKE private keys. The library's `BoringSSLAsymmetricCipherKeyPair.toString()` and `BoringSSLAsymmetricKeyParameter.toString()` methods explicitly include raw private key byte arrays in their output. Furthermore, the `EVP_HPKE_KEY_init_or_throw` error-handling path in `BoringSSL.java` logs the full byte array of a failed private key initialization within an `IllegalArgumentException` message. 

Because Java logging frameworks and APM tools often automatically invoke `toString()` on objects during structured logging or log exception stack traces, this vulnerability can result in the silent persistence of sensitive cryptographic material in plain-text logs or telemetry systems. This exposure significantly impacts the confidentiality of encrypted Oblivious HTTP (OHTTP) traffic and undermines key rotation and incident response efforts. Defenders should prioritize auditing application logs for the presence of these byte arrays and ensure the library is updated to a non-vulnerable version once released.

## Attack Chain

1. Application initializes an HPKE key pair using the vulnerable `netty-incubator-codec-ohttp-hpke-classes-boringssl` library.
2. The application performs a cryptographic operation or encounters a malformed key during initialization.
3. The `BoringSSLAsymmetricCipherKeyPair` or `BoringSSLAsymmetricKeyParameter` object is passed to a logging statement (e.g., `logger.debug("KeyPair: {}", pair)`).
4. The logging framework triggers the `toString()` method, which concatenates the raw private key bytes into the log string.
5. Alternatively, the application catches an `IllegalArgumentException` thrown by `EVP_HPKE_KEY_init_or_throw` and logs the exception message.
6. The raw private key bytes are written to the application's local log file or streamed to centralized log management (SIEM/ELK).
7. Unauthorized users with access to the log repository perform searches or extraction to recover the sensitive private key material.
8. The adversary uses the recovered key to decrypt intercepted OHTTP traffic or authenticate unauthorized messages.

## Impact

Successful exploitation leads to the compromise of HPKE private keys, resulting in a total loss of confidentiality for all OHTTP traffic encrypted with those keys. The retention of key material in logs creates a long-term exposure window, as adversaries can recover keys long after they have been rotated in application memory. The number of impacted systems corresponds to all deployments utilizing versions 0.0.22.Final or earlier of the affected library.

## Recommendation

- Upgrade `netty-incubator-codec-ohttp-hpke-classes-boringssl` to the latest patched version immediately upon release (CVE-2026-61798).
- Search enterprise log management systems for pattern matches resembling the leaked key representation, such as `"bytes=[0-9, ]+"` occurring within `BoringSSLAsymmetricKeyParameter` objects.
- Implement log redaction patterns in logging configurations (e.g., Log4j/Logback filters) to strip sensitive strings or objects associated with the library.
- Audit existing logs for high-risk assets to identify if private key material has been exposed historically.
- Apply the mitigation of redacting `toString()` outputs in custom wrappers if updating the library is delayed.
