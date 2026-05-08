---
title: fast-xml-builder Vulnerability Allows Attribute Injection
slug: 2024-01-fast-xml-builder-injection
description: The fast-xml-builder library allows attribute injection when handling attribute values containing quotes, leading to potential execution of arbitrary code.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xml
  - injection
  - xss
  - cve-2026-44665
vendors:
  - NPM
products:
  - fast-xml-builder (<= 1.1.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-5wm8-gmm8-39j9
rules:
  - title: Detect CVE-2026-44665 Exploitation Attempt via Attribute Injection
    description: Detects CVE-2026-44665 exploitation attempt — Detects suspicious attribute values with embedded JavaScript events that could be exploited by fast-xml-builder.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect fast-xml-builder Attribute Splitting Vulnerability - Suspicious Characters
    description: Detects possible exploitation of fast-xml-builder due to attribute splitting by searching for unusual characters in attribute values.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The fast-xml-builder npm package, version 1.1.6 and earlier, is susceptible to an attribute injection vulnerability (CVE-2026-44665). When processing XML/HTML with attribute values containing quotes, and the `processEntities` flag is disabled, the library incorrectly parses the input. This parsing failure leads to the breaking of the attribute value into multiple attributes, which can allow an attacker to inject arbitrary attributes, including those containing malicious code, into the resulting XML/HTML. This issue can occur in any application using fast-xml-builder to generate XML from user-controlled input, potentially leading to cross-site scripting (XSS) or other injection-based attacks.

## Attack Chain

1. An attacker crafts malicious input data containing quoted attribute values intended for XML/HTML generation.
2. The attacker injects the crafted data into an application using fast-xml-builder.
3. The application utilizes fast-xml-builder to process the data and generate XML/HTML output, with the `processEntities` flag disabled.
4. Due to the vulnerability, fast-xml-builder incorrectly parses the attribute value, splitting it into multiple attributes.
5. The injected malicious attributes are incorporated into the resulting XML/HTML structure.
6. The application sends the malformed XML/HTML response to a user.
7. The user's browser renders the page, executing the injected malicious code (e.g., JavaScript).
8. The attacker achieves cross-site scripting (XSS) or other injection-based attacks, leading to potential data theft or compromise of the user's session.

## Impact

Successful exploitation of this vulnerability allows attackers to inject arbitrary HTML attributes into XML documents. This can lead to cross-site scripting (XSS) attacks if the generated XML is used in a web application. Given the widespread use of fast-xml-builder in Node.js projects, a large number of applications could be vulnerable. The impact ranges from defacement and information theft to complete compromise of user accounts.

## Recommendation

*   Upgrade to a patched version of `fast-xml-builder` if one becomes available or use a different XML builder library.
*   As a temporary workaround, ensure the `processEntities` flag is set to `true` when using `fast-xml-builder`, as mentioned in the advisory.
*   Deploy the Sigma rule below to identify potential exploitation attempts by detecting suspicious attribute values being passed to the vulnerable library.
