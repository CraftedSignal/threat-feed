---
brief_id: brief-2024-01-03-openam-rce
event_id: brief-2024-01-03-openam-rce
revision: 1
activity_at: "2024-01-03T12:00:00Z"
title: OpenAM Pre-Authentication RCE via JATO ClientSession Deserialization
slug: 2024-01-openam-rce
description: OpenIdentityPlatform OpenAM is vulnerable to pre-authentication Remote Code Execution (RCE) via unsafe Java deserialization of the `jato.clientSession` HTTP parameter, allowing unauthenticated attackers to execute arbitrary commands on the server.
date: "2024-01-03T12:00:00Z"
lastmod: "2026-10-28T06:46:41Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:openidentityplatform:openam:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-IBONOK-CVE-2026-33439-POC&utm_source=rss&utm_medium=rss
tags:
  - openam
  - rce
  - deserialization
vendors:
  - OpenIdentityPlatform
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
cves:
  - id: CVE-2026-33439
    cvss: 9.8
    epss: 0.09333
    kev_status: "false"
  - id: CVE-2021-35464
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-2cqq-rpvq-g5qj
  - https://portswigger.net/research/pre-auth-rce-in-forgerock-openam-cve-2021-35464
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-IBONOK-CVE-2026-33439-POC&utm_source=rss&utm_medium=rss
rules:
  - title: Detect OpenAM JATO ClientSession Deserialization Attempt
    description: Detects attempts to exploit the OpenAM JATO clientSession deserialization vulnerability by monitoring for requests with a large base64 encoded string in the 'jato.clientSession' parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
  - title: Detect OpenAM POST Request with JATO ClientSession Parameter
    description: Detects suspicious POST requests to OpenAM with the 'jato.clientSession' parameter, potentially indicating a deserialization attack.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-10-28T06:46:41Z"
    level: L2
    summary: poc_available; added CVE-2026-33439
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-IBONOK-CVE-2026-33439-POC&utm_source=rss&utm_medium=rss
---

OpenIdentityPlatform OpenAM 16.0.5, and likely earlier versions, is susceptible to a critical pre-authentication Remote Code Execution (RCE) vulnerability. This flaw stems from the unsafe Java deserialization of the `jato.clientSession` HTTP parameter. Unlike the patched `jato.pageSession` parameter (CVE-2021-35464), `jato.clientSession` lacks proper input validation, allowing an unauthenticated attacker to inject a malicious serialized Java object. Successful exploitation grants the attacker the ability to execute arbitrary operating system commands with the privileges of the application server user. The vulnerability affects any OpenAM deployment that exposes a JATO endpoint with `<jato:form>` tags in its JSP pages, such as those used for password resets, making it a widespread threat to OpenAM installations.

## Attack Chain

1.  The attacker identifies an OpenAM endpoint that uses JATO ViewBeans and contains `<jato:form>` tags in its JSP (e.g., the password reset page).
2.  The attacker crafts a malicious serialized Java object designed to execute arbitrary commands. This payload leverages the `PriorityQueue`, `Column$ColumnComparator`, `PropertyUtils`, `TemplatesImpl`, and `EvilTranslet` classes bundled within the OpenAM WAR file.
3.  The attacker encodes the malicious serialized object using HTTP Base64 encoding.
4.  The attacker sends an HTTP GET or POST request to the vulnerable endpoint, including the Base64-encoded payload as the value of the `jato.clientSession` parameter.
5.  The OpenAM server receives the request and passes the `jato.clientSession` parameter to `RequestContextImpl.getClientSession()`.
6.  During JSP rendering, the `<jato:form>` tag invokes `getClientSession()`, which in turn calls `hasAttributes()`, `getEncodedString()`, `isValid()`, and finally `ensureAttributes()`, triggering `deserializeAttributes()`.
7.  The `deserializeAttributes()` method in `ClientSession.java` deserializes the `jato.clientSession` parameter using `Encoder.deserialize()` and `ApplicationObjectInputStream.readObject()` without proper input validation.
8.  The malicious serialized object is deserialized, leading to the execution of the injected `EvilTranslet` bytecode and the execution of arbitrary OS commands.

## Impact

The pre-authentication nature of this RCE vulnerability allows attackers to compromise OpenAM servers without requiring valid credentials or session tokens. A successful exploit can lead to full server compromise, enabling lateral movement within the network, data exfiltration, and other malicious activities. The vulnerability affects any OpenAM deployment with at least one accessible JATO endpoint whose JSP renders `<jato:form>` tags. OpenAM 16.0.5 is confirmed to be vulnerable and earlier versions are likely affected.

## Recommendation

*   Apply `WhitelistObjectInputStream` filtering to `ClientSession.deserializeAttributes()` in `com/iplanet/jato/ClientSession.java`, mirroring the mitigation already in place for `ConsoleViewBeanBase.deserializePageAttributes()`.
*   Deploy the Sigma rule "Detect OpenAM JATO ClientSession Deserialization Attempt" to monitor for exploitation attempts targeting the `jato.clientSession` parameter.
*   Audit all callers of `Encoder.deserialize()` for user-controlled input to identify and mitigate other potential deserialization vulnerabilities.
*   As a defense-in-depth measure, consider implementing a JVM-wide JEP 290 deserialization filter to restrict deserialization to trusted classes.
