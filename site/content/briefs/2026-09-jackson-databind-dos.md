---
title: Denial of Service via Unbounded Numeric Deserialization in Jackson Databind
slug: 2026-09-jackson-databind-dos
description: A vulnerability in jackson-databind allows unauthenticated attackers to cause CPU exhaustion and denial of service by supplying specially crafted strings that bypass length constraints during XML datatype deserialization.
date: "2026-09-28T22:15:35Z"
lastmod: "2026-09-30T16:27:17Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:fasterxml:jackson-databind:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - deserialization
  - library-vulnerability
  - java
  - json
  - cve-2026-91777
  - memory-exhaustion
  - cve-2026-91776
vendors:
  - FasterXML
products:
  - jackson-databind (>= 3.2.0, < 3.2.2)
  - jackson-databind (>= 3.0.0, < 3.1.6)
  - jackson-databind (>= 2.14.0, < 2.18.10)
  - jackson-databind (>= 2.19.0, < 2.21.6)
  - jackson-databind (>= 2.22.0, < 2.22.2)
  - jackson-databind (2.5.0 - 2.18.10)
  - jackson-databind (2.19.0 - 2.21.6)
  - jackson-databind (2.22.0 - 2.22.2)
  - jackson-databind (3.0.0 - 3.1.6)
  - jackson-databind (3.2.0 - 3.2.2)
  - jackson-databind (>= 2.0.0, <= 2.18.10)
  - jackson-databind (>= 2.19.0, <= 2.21.6)
  - jackson-databind (>= 2.22.0, <= 2.22.2)
  - jackson-databind (>= 3.0.0, <= 3.1.6)
  - jackson-databind (>= 3.2.0, <= 3.2.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker can submit a single small request that forces tens of seconds to minutes of single-thread CPU consumption, yielding a denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-68497
    cvss: 7.5
    epss: 0.00581
references:
  - https://github.com/advisories/GHSA-q4xh-88c3-wmh7
  - https://nvd.nist.gov/vuln/detail/CVE-2026-68497
  - https://github.com/advisories/GHSA-cxp5-3px4-pw24
  - https://github.com/advisories/GHSA-wv8q-qhhj-9h54
updates:
  - at: "2026-09-30T16:27:07Z"
    level: L1
    summary: added coverage for jackson-databind (2.5.0 - 2.18.10) +4 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-cxp5-3px4-pw24
  - at: "2026-09-30T16:27:17Z"
    level: L1
    summary: added coverage for jackson-databind (>= 2.0.0, <= 2.18.10) +4 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-wv8q-qhhj-9h54
---

Jackson-databind versions 3.2.1 and earlier, along with specific versions of the 2.x branch, contain a denial of service vulnerability (CVE-2026-68497) triggered by the deserialization of `javax.xml.datatype.Duration` and `XMLGregorianCalendar` objects. The library passes raw JSON string tokens directly to the JDK's `DatatypeFactory.newDuration()` or `newXMLGregorianCalendar()` methods without applying length validation. While `jackson-core` enforces a `maxNumberLength` constraint for JSON number tokens, this guard does not apply to digits encapsulated within a JSON string token. 

Because the JDK materializes these numeric components into `java.math.BigInteger` or `BigDecimal` using constructors with O(n²) complexity, an attacker can supply a small payload (e.g., 1 - 5 MB) that results in significant CPU consumption lasting for minutes. This behavior allows an unauthenticated attacker to saturate server worker threads with a limited number of requests, effectively denying service to legitimate traffic. The vulnerability is present in default configurations of the `JsonMapper` and does not require advanced features like polymorphic typing to exploit.

## Attack Chain

1. Attacker identifies an internet-facing application that uses `jackson-databind` to deserialize JSON into POJOs containing `javax.xml.datatype.Duration` or `XMLGregorianCalendar` fields.
2. Attacker constructs a malicious JSON payload where the field value is a string containing an extremely long sequence of numeric characters (e.g., "P" + 5,000,000 nines + "Y").
3. Attacker submits the payload via an HTTP POST request to the application's API endpoint.
4. The `jackson-databind` library performs default deserialization and identifies the target field type.
5. The library passes the attacker-supplied string token to `CoreXMLDeserializers`, which omits a length check against the string content.
6. The `DatatypeFactory` parses the string, invoking the O(n²) `BigInteger(String)` or `BigDecimal(String)` constructors within the JDK.
7. The server CPU utilization spikes to 100% for the duration of the parsing process, causing thread exhaustion and blocking subsequent requests.

## Impact

Successful exploitation results in a persistent denial of service condition. A single small request of approximately 5 MB can consume several minutes of single-threaded CPU time. By orchestrating a low-volume, concurrent stream of such requests, an attacker can fully exhaust available application worker threads, leading to application-wide unavailability. This vulnerability impacts any service utilizing affected versions of `jackson-databind` to process user-supplied configuration or XML-derived data models.

## Recommendation

1. Upgrade `jackson-databind` to a patched version immediately: 2.18.10, 2.21.6, 2.22.2, 3.1.6, or 3.2.2.
2. If immediate patching is not feasible, implement a transport-layer length constraint on all JSON inputs to reject payloads containing abnormally long strings destined for XML-datatype fields.
3. Review application DTOs for fields typed `javax.xml.datatype.Duration` or `XMLGregorianCalendar` and implement custom deserializers that enforce strict length bounds on the input string before passing it to the JDK factory methods.
