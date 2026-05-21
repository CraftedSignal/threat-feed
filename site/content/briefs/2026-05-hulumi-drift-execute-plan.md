---
title: '@hulumi/drift Orphan Reconciler Accepts Externally Supplied Execute Plans'
slug: 2026-05-hulumi-drift-execute-plan
description: '@hulumi/drift versions before 1.3.2 could accept externally supplied execute plans without sufficient provenance checks, allowing unsafe reconciliation input to be treated as trusted; upgrade to version 1.3.2 or later to resolve this vulnerability.'
date: "2026-05-21T20:45:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - vulnerability
  - npm
vendors:
  - GitHub
products:
  - '@hulumi/drift (< 1.3.2)'
  - github.com
references:
  - https://github.com/advisories/GHSA-2ffm-hxrq-qqmm
rules:
  - title: Detect Suspicious Activity Related to @hulumi/drift Execute Plans
    description: Detects potentially malicious activity related to the processing of execute plans in applications using @hulumi/drift, indicating a possible attempt to exploit GHSA-2ffm-hxrq-qqmm.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - linux
  - title: Detect Usage of Vulnerable @hulumi/drift Versions
    description: Detects the use of vulnerable versions of the @hulumi/drift package, indicating a system may be susceptible to GHSA-2ffm-hxrq-qqmm.
    platform: sigma
    severity: high
    tactics:
      - vulnerability
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

@hulumi/drift, a package available on npm and used in the `kerberosmansour/hulumi` repository, was found to have a vulnerability where it could accept externally supplied execute plans without properly validating their provenance. This issue, affecting versions prior to 1.3.2, allows potentially unsafe reconciliation input to be processed as trusted, posing a risk to applications utilizing this package. Version 1.3.2 introduces enhanced execute-plan handling with provenance validation and regression coverage. This vulnerability could allow attackers to manipulate the reconciliation process, potentially leading to unintended or malicious outcomes.

## Attack Chain

This attack chain describes the potential exploitation of the vulnerability where @hulumi/drift accepts externally supplied execute plans without proper validation.

1. An attacker crafts a malicious execute plan designed to manipulate the reconciliation process.
2. The attacker supplies the crafted execute plan to an application using a vulnerable version of @hulumi/drift.
3. @hulumi/drift, lacking sufficient provenance checks, accepts the externally supplied execute plan.
4. The application processes the malicious execute plan, treating it as a trusted input.
5. The reconciliation process is influenced by the attacker's crafted plan, leading to unintended consequences.
6. The attacker achieves their objective, which could include data manipulation, privilege escalation, or denial of service, depending on the application's functionality and the scope of the reconciliation process.

## Impact

Successful exploitation of this vulnerability could lead to a compromise of the integrity of applications using the vulnerable versions of @hulumi/drift. By supplying malicious execute plans, attackers can manipulate the reconciliation process, potentially leading to unauthorized data modification or unintended system behavior. This could have significant consequences for applications relying on the integrity of the reconciliation process.

## Recommendation

- Upgrade @hulumi/drift to version 1.3.2 or later to remediate the vulnerability as advised in the GitHub Advisory [GHSA-2ffm-hxrq-qqmm](https://github.com/advisories/GHSA-2ffm-hxrq-qqmm).
- Implement additional input validation and sanitization measures within applications using @hulumi/drift to further mitigate the risk of malicious input.
