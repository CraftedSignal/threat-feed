---
title: Keystone GraphQL maxTake Argument Injection
slug: 2026-08-keystone-graphql-bypass
description: The Keystone @keystone-6/core package is vulnerable to a GraphQL input validation flaw, CVE-2026-63421, where negative values in the 'take' argument bypass configured result limits.
date: "2026-08-22T01:17:37Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - Keystone
products:
  - Keystone Core (6.5.2)
cves:
  - id: CVE-2026-63421
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-cqmq-8755-7xvh
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63421
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade @keystone-6/core to 6.5.3
      owner: IT Operations
      due: 48h
      evidence: Source states issue has been patched in version 6.5.3
  mitigation_plan:
    - priority: immediate
      action: WAF block for negative take arguments in GraphQL
      owner: Application Security
      addresses: CVE-2026-63421
      evidence: Workaround suggested in source documentation
---

Keystone versions 6.5.2 and earlier contain a vulnerability in the GraphQL layer (CVE-2026-63421) related to input validation of the 'take' argument. The 'take' argument is intended to constrain the number of records returned in a query, which is protected by the 'graphql.maxTake' configuration setting. Attackers can bypass this configuration limit by supplying a negative integer for the 'take' argument, causing the application to return an excessive number of records beyond the defined threshold. This can result in unauthorized mass data exposure or server performance degradation due to resource-heavy queries. The vulnerability was discovered by Haxset and addressed in version 6.5.3 of the @keystone-6/core package.

## Impact

Successful exploitation allows for the exfiltration of significantly more data than intended by the application developer. This impacts any Keystone-based application that relies on 'graphql.maxTake' as a security or performance control mechanism to bound database result sets.

## Recommendation

- Upgrade the @keystone-6/core package to version 6.5.3 or later across all production deployments.
- If immediate patching is not feasible, implement request validation at the API gateway or WAF layer to block GraphQL queries containing negative values for the 'take' argument.
- Audit existing GraphQL query patterns for abnormally high result counts that may indicate exploitation of this vulnerability.
