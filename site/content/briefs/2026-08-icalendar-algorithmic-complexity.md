---
title: Denial of Service Vulnerability in icalendar Python Library
slug: 2026-08-icalendar-algorithmic-complexity
description: The icalendar Python library contains an algorithmic complexity vulnerability (CVE-2026-55099) in the Component.__eq__ method that allows for denial of service via deeply nested subcomponents.
date: "2026-08-26T00:50:55Z"
type: advisory
types:
  - advisory
severities:
  - low
products:
  - icalendar (7.1.0 to 7.1.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: By supplying a specially crafted .ics file, a sub-kilobyte file is enough to make a single equality check run for minutes or hang indefinitely.
    confidence_band: high
cves:
  - id: CVE-2026-55099
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-cv84-9p8j-fj68
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55099
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade icalendar library to v7.1.3 or higher across all production environments.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-55099 fix available in v7.1.3.
  mitigation_plan:
    - priority: medium_term
      action: Implement depth-limiting logic for iCalendar parsing to prevent malicious nested structures.
      owner: Application Security
      addresses: CVE-2026-55099
      evidence: Parser does not gate component nesting depth.
---

The Python library `icalendar` (versions 7.1.0 through 7.1.2) contains an algorithmic complexity vulnerability in its `Component.__eq__` method, which is used for comparing iCalendar objects. The vulnerability exists because the library performs recursive equality checks on nested subcomponents with an O(2^n) time complexity. By supplying a specially crafted iCalendar file containing deeply nested components, an attacker can trigger a denial-of-service condition, causing the application to consume excessive CPU resources and hang indefinitely during equality or membership comparison operations. 

This issue is significant for any application that processes untrusted iCalendar data and subsequently performs comparison operations such as `==`, `!=`, or membership tests (e.g., in sets or dictionaries), including services that perform deduplication, calendar synchronization, or normalization checks. The vulnerability is triggered only when comparison logic is executed on the parsed structure, not during the parsing phase itself.

## Impact

The vulnerability results in an algorithmic-complexity denial of service (CWE-407). A malicious actor can execute this attack without authentication by submitting an iCalendar file of less than 1KB. This single request can pin a CPU core for minutes, resulting in service unavailability. The impact is widespread among applications relying on the `icalendar` library for handling invites or calendar imports, particularly if the application performs automatic round-trip normalization or deduplication.

## Recommendation

* Update the `icalendar` package to version 7.1.3 or later where the equality logic has been refactored to use an explicit stack to walk components, reducing complexity to linear time.
* Audit applications that use the `icalendar` library to identify code paths where `Component` objects are compared for equality, added to sets, or used in membership tests using input from untrusted sources.
* Implement input validation to restrict the depth of nested components in incoming iCalendar files before passing them to the library for processing.
