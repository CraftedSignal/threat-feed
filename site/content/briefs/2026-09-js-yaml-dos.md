---
title: Denial of Service Vulnerability in js-yaml via Empty Merge Source Exhaustion
slug: 2026-09-js-yaml-dos
description: The js-yaml library fails to correctly account for empty mappings when enforcing maxTotalMergeKeys, allowing attackers to trigger excessive CPU consumption through specially crafted YAML documents.
date: "2026-09-08T21:50:18Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - vulnerability
  - denial-of-service
  - supply-chain
products:
  - js-yaml (>= 4.0.0, < 4.3.2)
  - js-yaml (>= 3.0.0, < 3.15.2)
cves:
  - id: CVE-2026-84375
    cvss: 7.5
    epss: 0.00385
references:
  - https://github.com/advisories/GHSA-2883-xcg3-v3hh
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-84375
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Audit environment for vulnerable versions of js-yaml (CVE-2026-84375)
      owner: Development
      due: 48h
      evidence: CVE-2026-84375
  mitigation_plan:
    - priority: immediate
      action: Upgrade js-yaml to 3.15.2 or 4.3.2
      owner: Development
      addresses: CVE-2026-84375
      evidence: GHSA-2883-xcg3-v3hh
---

The js-yaml library (versions 3.x < 3.15.2 and 4.x < 4.3.2) is vulnerable to a denial-of-service (DoS) condition due to an incorrect implementation of merge key counting. The `maxTotalMergeKeys` configuration is intended to limit the computational complexity of parsing YAML documents; however, it does not count empty mappings towards this limit. An attacker can supply a YAML payload consisting of a large sequence of empty mappings that are repeatedly merged, resulting in an O(N*K) complexity increase. This allows for high CPU utilization using a relatively small file size, effectively bypassing configured protections. This vulnerability (CVE-2026-84375) is particularly impactful in applications that accept untrusted YAML input, as the parser consumes excessive cycles, potentially leading to resource exhaustion and service unavailability.

## Impact

Successful exploitation results in high CPU consumption, causing service degradation or total unavailability for applications parsing malicious YAML documents. This is a supply chain vulnerability affecting any JavaScript application that relies on the `js-yaml` library for processing user-supplied data, such as configuration files, user data imports, or API requests.

## Recommendation

1. Upgrade `js-yaml` to versions 3.15.2 or 4.3.2 or later to include the fix that correctly counts empty merge-source mappings.
2. Perform a dependency audit of your projects using `npm list js-yaml` or `yarn why js-yaml` to identify vulnerable versions.
3. If immediate patching is not possible, implement strict file size limits and timeout configurations on any server-side service that triggers the `js-yaml` parser on untrusted input.
4. Ensure that the `maxTotalMergeKeys` configuration is enabled and set to a strict value appropriate for your application requirements.
