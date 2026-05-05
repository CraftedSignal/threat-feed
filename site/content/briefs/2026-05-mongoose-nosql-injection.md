---
title: Mongoose NoSQL Injection Vulnerability via $nor Operator
slug: 2026-05-mongoose-nosql-injection
description: Mongoose versions before 6.13.9, versions 7.0.0 through 7.8.8, versions 8.0.0 through 8.22.0, and versions 9.0.0 through 9.1.5 are vulnerable to NoSQL injection due to improper sanitization of the $nor operator, potentially allowing attackers to bypass query sanitization and exfiltrate data.
date: "2026-05-05T21:49:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - nosql-injection
  - mongoose
  - sanitizeFilter
vendors:
  - Mongoose
products:
  - mongoose < 6.13.9
  - mongoose >= 7.0.0, <= 7.8.8
  - mongoose >= 8.0.0, <= 8.22.0
  - mongoose >= 9.0.0, <= 9.1.5
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://github.com/advisories/GHSA-wpg9-53fq-2r8h
  - https://mongoosejs.com/docs/api/mongoose.html#Mongoose.prototype.sanitizeFilter()
  - https://thecodebarbarian.com/whats-new-in-mongoose-6-sanitizefilter.html
rules:
  - title: Detect $nor Operator in Query Parameters
    description: Detects the presence of the $nor operator in web server query parameters, potentially indicating NoSQL injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect $nor Operator in HTTP POST Request Body
    description: Detects the presence of the $nor operator in HTTP POST request bodies, potentially indicating NoSQL injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Mongoose, a MongoDB object modeling tool designed to work in an asynchronous environment, is susceptible to a NoSQL injection vulnerability. Specifically, the `sanitizeFilter` function fails to properly sanitize the `$nor` operator, leading to potential bypass of query sanitization mechanisms. This issue affects Mongoose versions prior to 6.13.9, versions between 7.0.0 and 7.8.8, versions between 8.0.0 and 8.22.0, and versions between 9.0.0 and 9.1.5. Successful exploitation could lead to unauthorized data access, authentication bypass, and data exfiltration. Defenders should prioritize patching or implementing workarounds to mitigate this risk.

## Attack Chain

1.  An attacker identifies an application using a vulnerable version of Mongoose with `sanitizeFilter` enabled.
2.  The attacker crafts a malicious payload containing a `$nor` operator with an embedded, unsanitized operator (e.g., `$ne`, `$gt`, or `$regex`).
3.  The attacker injects the malicious payload into a user-controlled input field, such as a search parameter or login field.
4.  The application passes the unsanitized input directly to a Mongoose query method (e.g., `Model.findOne(req.body)`).
5.  Mongoose's `sanitizeFilter` function fails to properly sanitize the `$nor` operator, allowing the malicious operator to bypass sanitization.
6.  The malicious operator is executed against the MongoDB database.
7.  The attacker bypasses authentication, gains unauthorized data access, or exfiltrates sensitive information.

## Impact

Successful exploitation of this vulnerability can lead to significant impact, including authentication bypass, where attackers can gain access to user accounts without proper credentials. Unauthorized data access allows attackers to view and modify sensitive data that they should not have access to. Data exfiltration enables attackers to steal confidential information from the database. Organizations using vulnerable versions of Mongoose are at risk.

## Recommendation

*   Upgrade to Mongoose version 6.13.9 or later, 7.8.9 or later, 8.22.1 or later, or 9.1.6 or later to patch the vulnerability as described in [GHSA-wpg9-53fq-2r8h](https://github.com/advisories/GHSA-wpg9-53fq-2r8h).
*   Deploy the following Sigma rule to detect the use of `$nor` in query parameters to `webserver` logs and tune for your environment.
*   Implement a workaround by deleting `$nor` keys or using an additional schema validation library as recommended in [GHSA-wpg9-53fq-2r8h](https://github.com/advisories/GHSA-wpg9-53fq-2r8h).
