---
title: Multiparty Denial of Service via Prototype Pollution (CVE-2026-8161)
slug: 2026-05-multiparty-dos
description: Multiparty versions 4.2.3 and lower are vulnerable to denial of service via prototype pollution, where a crafted multipart/form-data request with a field name colliding with an Object.prototype property triggers a TypeError, leading to an uncaught exception and process crash.
date: "2026-05-18T17:38:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:pillarjs:multiparty:*:*:*:*:*:node.js:*:*
tags:
  - prototype-pollution
  - denial-of-service
  - nodejs
vendors:
  - npm
products:
  - multiparty (<= 4.2.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
cves:
  - id: CVE-2026-8161
    cvss: 7.5
    epss: 0.00039
references:
  - https://github.com/advisories/GHSA-qxch-whhj-8956
  - CVE-2026-8161
rules:
  - title: Detect CVE-2026-8161 Exploitation Attempt via Multipart Form
    description: Detects CVE-2026-8161 exploitation attempt — HTTP POST requests with multipart/form-data containing field names that collide with Object.prototype properties.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.002
    data_sources:
      - webserver
  - title: Detect CVE-2026-8161 Exploitation Attempt via Multipart Form (URI Stem)
    description: Detects CVE-2026-8161 exploitation attempt — HTTP POST requests with multipart/form-data containing field names that collide with Object.prototype properties in the URI stem.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.002
    data_sources:
      - webserver
rules_count: 2
---

Multiparty is a Node.js module for handling multipart/form-data requests. Versions 4.2.3 and earlier are vulnerable to a denial-of-service (DoS) attack. By sending a specially crafted `multipart/form-data` request, an attacker can trigger a prototype pollution vulnerability.  Specifically, a field name that overlaps with a property inherited from `Object.prototype` (such as `__proto__`, `constructor`, or `toString`) causes the parser to attempt a `.push()` operation on the prototype value instead of an array. This results in a `TypeError` that is not caught, leading to an uncaught exception that crashes the Node.js process. This affects any service that uses multiparty to handle file uploads or form data.  The vulnerability is identified as CVE-2026-8161.

## Attack Chain

1. Attacker identifies a web service using a vulnerable version of multiparty (<= 4.2.3) for handling `multipart/form-data` requests.
2. Attacker crafts an HTTP POST request with `Content-Type: multipart/form-data`.
3. The crafted request includes a form field where the name of the field is a property of `Object.prototype`, such as `__proto__`.
4. The multiparty library attempts to parse the `multipart/form-data` request.
5. During parsing, multiparty attempts to call the `.push()` method on the `__proto__` property. Since `__proto__` is not an array, this results in a `TypeError`.
6. The `TypeError` is not caught by the multiparty library's error handling.
7. The uncaught exception propagates to the Node.js process's event loop.
8. The Node.js process crashes due to the uncaught exception, causing a denial of service.

## Impact

Successful exploitation of this vulnerability results in a denial of service. Any service using the vulnerable multiparty library to handle multipart form data can be crashed by a malicious actor. The number of potential victims is widespread, as multiparty is a commonly used library in Node.js web applications. This can lead to service unavailability and potential data loss if the application does not handle restarts gracefully.

## Recommendation

*   Upgrade to `multiparty@4.3.0` or higher to patch the vulnerability as per the advisory.
*   Deploy the Sigma rule "Detect CVE-2026-8161 Exploitation Attempt via Multipart Form" to detect requests attempting to exploit this vulnerability by sending requests with a field name overlapping with a property of `Object.prototype`.
*   Implement rate limiting on endpoints that accept multipart form data to mitigate the impact of denial-of-service attacks in general.
