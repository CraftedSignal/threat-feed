---
title: Prototype Pollution Vulnerability in @rvf/set-get
slug: 2026-10-rvf-prototype-pollution
description: The @rvf/set-get library prior to version 7.0.4 is vulnerable to prototype pollution, allowing unauthenticated attackers to trigger a process-wide denial of service via malicious form field submissions.
date: "2026-10-19T18:08:48Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:rvf:set-get:*:*:*:*:*:*:*:*
vendors:
  - rvf
products:
  - '@rvf/set-get (< 7.0.4)'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Attackers can submit a form field named hasOwnProperty.call through @rvf/core form parsing to replace the shared function property, causing process-wide denial of service until restart.
    confidence_band: high
cves:
  - id: CVE-2026-112309
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112309
---

The @rvf/set-get library before version 7.0.4 contains a prototype pollution vulnerability within its setPath function. This flaw allows unauthenticated attackers to manipulate the prototype chain of built-in JavaScript objects. By submitting crafted input through form parsing mechanisms in @rvf/core, an attacker can target and overwrite properties of shared built-in functions, such as hasOwnProperty.call. When successfully exploited, this manipulation corrupts the execution context of the application, leading to a process-wide denial of service that requires a full application restart to resolve. This vulnerability is significant for web applications utilizing these libraries for form handling, as it enables an unauthenticated remote attacker to crash service availability.

## Attack Chain

1. Attacker identifies a web application utilizing @rvf/set-get (< 7.0.4) and @rvf/core for form input processing.
2. Attacker crafts a malicious HTTP request containing a specially named form field, such as 'hasOwnProperty.call'.
3. The @rvf/core component parses the incoming form data and passes the fields to the vulnerable setPath function within @rvf/set-get.
4. The setPath function fails to properly sanitize the input, allowing the attacker-controlled key to traverse the prototype chain.
5. The library performs an assignment that overwrites a shared built-in function property on Object.prototype.
6. Subsequent application logic attempting to use the corrupted built-in function fails.
7. The application encounters a critical runtime error due to the corrupted prototype, resulting in a process-wide denial of service.

## Impact

Successful exploitation results in a persistent denial of service (DoS) for the affected application instance. The vulnerability allows an unauthenticated remote attacker to disrupt availability by crashing the server process. Because the corruption occurs on the global Object.prototype, the impact is process-wide, rendering the application unstable until it is manually restarted by administrators.

## Recommendation

* Upgrade the @rvf/set-get library to version 7.0.4 or later immediately.
* Audit applications using @rvf/core to ensure that input validation is performed before data is passed to helper libraries, as a defense-in-depth measure against prototype pollution.
* Monitor application logs for unexpected crashes or errors related to missing or corrupted built-in JavaScript functions.
