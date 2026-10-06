---
title: PyMongo Host Injection via Percent-Encoded Delimiters
slug: 2026-10-pymongo-host-injection
description: A vulnerability in PyMongo (CVE-2026-96748) allows attackers to inject malicious host entries into connection strings via percent-encoded delimiters, potentially leading to unauthorized data routing or credential theft.
date: "2026-10-06T06:43:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mongodb:pymongo:*:*:*:*:*:python:*:*
tags:
  - pymongo
  - injection
  - database
  - vulnerability
vendors:
  - MongoDB
products:
  - PyMongo (3.5.0 - 4.18.1)
cves:
  - id: CVE-2026-96748
    cvss: 6.5
    epss: 0.00257
references:
  - https://github.com/advisories/GHSA-vp6j-j7w5-5xjj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96748
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade PyMongo to 4.18.2 or later across all production environments
      owner: IT Operations
      due: 48h
      evidence: Fixed in PyMongo 4.18.2.
  mitigation_plan:
    - priority: immediate
      action: Remove or sanitize user input used in connection string construction
      owner: Application Security
      addresses: CVE-2026-96748
      evidence: Do not interpolate untrusted input into the host portion of a connection string.
---

PyMongo versions 3.5.0 through 4.18.1 contain a host injection vulnerability (CVE-2026-96748) resulting from improper parsing of connection strings. The driver performs global percent-decoding on the host component of the connection string before splitting the string into individual `host:port` targets. An attacker who can influence the input interpolated into a connection string (such as user-provided hostnames or identifiers) can inject a comma (`%2C`) or colon (`%3A`) into the input. These sequences are ignored by many URL-validation checks but are decoded into functional delimiters by PyMongo, allowing the attacker to inject an arbitrary server into the client's seed list. This exposes the application to topology discovery or authentication requests directed toward attacker-controlled infrastructure, potentially leaking credentials or allowing the redirection of database operations. The vulnerability was addressed in PyMongo 4.18.2 by deferring percent-decoding to apply only to specific Unix domain socket paths after host splitting has occurred.

## Attack Chain

1. Attacker identifies an application endpoint that accepts user-controlled input (e.g., tenant ID, hostname, or API key).
2. Attacker crafts a malicious input string containing encoded delimiters, such as `legit-db.example.com%2Cmalicious-host.com`.
3. The application blindly interpolates this string into a MongoDB connection URI.
4. The PyMongo client receives the connection URI and passes the host section to the vulnerable parsing logic.
5. The parser calls `unquote_plus` on the entire host segment, converting `%2C` to `,`.
6. The parser splits the resulting string into a list of hosts, now including the attacker-supplied `malicious-host.com`.
7. The PyMongo driver attempts to connect to or perform topology discovery against both the legitimate host and the attacker's host.
8. Attacker-controlled host receives authentication attempts or database operations, leading to credential harvesting or data exfiltration.

## Impact

Successful exploitation allows attackers to perform man-in-the-middle attacks, capture authentication credentials, and potentially reroute database operations. This vulnerability affects any application using PyMongo versions 3.5.0 through 4.18.1 that constructs connection strings using unsanitized or insufficiently validated user-provided data. While the scope of impact depends on the application's implementation, it represents a significant risk for multi-tenant applications or platforms that dynamically generate connection URIs.

## Recommendation

1. Upgrade all instances of PyMongo to version 4.18.2 or later immediately to patch CVE-2026-96748.
2. Audit application codebases for dynamic construction of MongoDB connection strings, specifically looking for string interpolation of user-supplied variables.
3. Implement strict input validation or allowlisting for any variables used in connection strings; prevent the injection of characters such as `%`, `:`, `,`, or `/`.
4. Use parameterized configuration management instead of constructing URIs at runtime where possible.
