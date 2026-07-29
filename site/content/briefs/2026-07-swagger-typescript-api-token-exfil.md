---
title: Swagger-typescript-api Vulnerable to Authorization Token Exfiltration via Spec $ref
slug: 2026-07-swagger-typescript-api-token-exfil
description: The `swagger-typescript-api` tool is vulnerable to authorization token exfiltration. When a developer provides an `--authorizationToken` to fetch an OpenAPI specification, the tool attaches this token to all subsequent HTTP requests made while resolving external `$ref` URLs within the spec. Critically, it lacks same-origin checks, allowing a malicious OpenAPI spec containing a `$ref` to an attacker-controlled URL to cause the authorization token (e.g., GitHub PAT, OAuth bearer) to be sent verbatim to the attacker. This credential disclosure provides an attacker with the same scope of access as the stolen token, affecting development environments, CI/CD pipelines, and multi-tenant SaaS platforms.
date: "2026-07-29T14:24:07Z"
lastmod: "2026-07-29T14:33:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-theft
  - supply-chain
  - software-development
  - openapi
  - api-security
  - nodejs
  - code-injection
  - npm
  - node.js
  - code-generation
products:
  - swagger-typescript-api (<= 13.12.1)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: 'The token is typically a high-value secret: a GitHub PAT, an OAuth bearer for the API the spec describes, an enterprise SSO token, an AWS-style API key, or similar. Disclosure to an attacker-controlled URL is one curl-equivalent away from full takeover of whatever scope the token grants.'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: A malicious OpenAPI spec containing a `$ref` to an attacker-controlled URL therefore causes the developer's bearer token to be sent verbatim to that URL during code generation.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: The attacker controls the OpenAPI spec; the victim is any consumer of the generated client.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A computed property key whose value is an IIFE executes arbitrary code every time new HttpClient() ... is constructed.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The PoC ... schedules `fs.readFileSync('/etc/passwd')`, and writes the exfiltrated contents to `/tmp/sta_canary`.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-h754-fxp7-88wx
  - https://github.com/advisories/GHSA-38c3-wv3c-v3xj
rules:
  - title: Detect Node.js Processes Accessing Sensitive System Files
    description: Detects CVE-2026-54661 post-exploitation behavior where a Node.js process might attempt to read sensitive system files like /etc/passwd or /etc/shadow as a result of arbitrary code execution.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - execution
    techniques:
      - T1003.008
      - T1059.007
    data_sources:
      - file_event
      - linux
rules_count: 1
updates:
  - at: "2026-07-29T14:33:31Z"
    level: L2
    summary: 'added detection rule: Detect Node.js Processes Accessing Sensitive System Files'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-38c3-wv3c-v3xj
---

The `swagger-typescript-api` tool, specifically versions up to and including 13.12.1, is vulnerable to authorization token exfiltration (CVE-2026-54660). This vulnerability arises when the tool is used to generate API clients from an OpenAPI specification, and a developer provides an `--authorizationToken` flag to authenticate against a private spec. The tool's `getRemoteRequestHeaders()` function unconditionally attaches this token to the `Authorization` header of *every* subsequent HTTP request made while resolving external `$ref` URLs within the specification. Crucially, it fails to perform a same-origin check, host allowlist, or scope-down, meaning that a maliciously crafted OpenAPI spec with an external `$ref` pointing to an attacker-controlled domain will cause the developer's sensitive token (such as a GitHub Personal Access Token, OAuth bearer token, or API key) to be sent verbatim to the attacker. This flaw poses a significant risk to development environments, CI/CD pipelines, and multi-tenant SaaS platforms, as the captured token grants attackers the same level of access as the legitimate developer.

## Attack Chain

1. An attacker crafts a malicious OpenAPI specification containing an external `$ref` pointing to an attacker-controlled URL (e.g., `http://attacker.example/exfil-endpoint/data.json`).
2. The attacker delivers this malicious spec to a developer or injects it into a trusted spec (e.g., via a compromised repository or supply chain attack).
3. A developer or automated CI/CD pipeline executes `swagger-typescript-api generate` against the malicious or compromised OpenAPI specification, supplying a sensitive authorization token via the `--authorizationToken` flag.
4. During the code generation process, `swagger-typescript-api` attempts to resolve the external `$ref` URLs defined within the spec.
5. The vulnerable `swagger-typescript-api` component `getRemoteRequestHeaders()` attaches the developer's full `--authorizationToken` value to the HTTP request without performing a same-origin check.
6. `swagger-typescript-api` makes an outbound HTTP GET request to the attacker-controlled URL, including the sensitive token in the `Authorization` header.
7. The attacker's server receives the request and captures the exposed authorization token.
8. The attacker can then use the stolen token to gain unauthorized access to the services or resources associated with the token's scope, mimicking the developer's privileges.

## Impact

The vulnerability, identified as CVE-2026-54660, directly leads to the exposure of sensitive credentials, typically high-value authorization tokens. The impact is significant, as the stolen token grants attackers the same scope of access as the developer or system it was stolen from. This could include full source-code read/write access via a GitHub Personal Access Token, full impersonation on an API via an OAuth bearer token, or extensive account access through an AWS-style API key, depending on the token's privileges. Affected use cases include developers fetching private OpenAPI specs, CI/CD pipelines regenerating clients from private specs, and multi-tenant SaaS platforms that generate per-tenant clients. The credential theft occurs at generation time, meaning the risk is realized as soon as `swagger-typescript-api generate` is run with a malicious spec and an authorization token.

## Recommendation

* Patch CVE-2026-54660 by upgrading `swagger-typescript-api` to a version greater than 13.12.1 as soon as a fix is released by the maintainers.
* Implement robust network egress filtering for systems running `swagger-typescript-api` to prevent outbound connections to untrusted external URLs, particularly on non-standard ports.
* Review and restrict the scope and lifetime of `--authorizationToken`s used with `swagger-typescript-api`, adhering to the principle of least privilege.
* Run `swagger-typescript-api` in isolated environments (e.g., containers, ephemeral build agents) with minimal network access and permissions, similar to the SSRF mitigations suggested in the companion advisory.
