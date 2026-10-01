---
title: Uncontrolled Resource Consumption in devalue Serialization
slug: 2026-10-devalue-quadratic-expansion
description: The devalue package for Node.js is vulnerable to a denial-of-service attack where specially crafted input causes quadratic string expansion during the serialization process, leading to memory and CPU exhaustion.
date: "2026-10-01T20:22:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - npm
  - supply-chain
vendors:
  - Svelte
products:
  - devalue (<= 5.9.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The product does not handle or incorrectly handles a compressed input with a very high compression ratio that produces a large output.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mcm9-63f2-9j32
  - https://github.com/sveltejs/devalue/releases/tag/v5.9.3
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Upgrade devalue package to 5.9.3
      owner: IT Operations
      due: 48h
      evidence: Remediation note in GHSA-mcm9-63f2-9j32
  mitigation_plan:
    - priority: immediate
      action: Upgrade devalue to 5.9.3
      owner: IT Operations
      addresses: CWE-400
      evidence: GHSA-mcm9-63f2-9j32
---

The devalue package for Node.js is susceptible to an uncontrolled resource consumption vulnerability (CWE-400, CWE-409) within its 'uneval' function. When handling specifically crafted data that has been previously parsed, the serialization process can trigger quadratic expansion. This results in a relatively small input payload being transformed into a disproportionately large serialized string. By exploiting this behavior, an attacker can cause the host application to exhaust available system memory and CPU resources, effectively resulting in a denial-of-service condition. This vulnerability affects all versions of devalue up to and including 5.9.2. Developers are urged to update to version 5.9.3 to mitigate this risk, as this patch addresses the logic error leading to the amplification effect.

## Attack Chain

1. An attacker identifies a web application or internal service that utilizes the 'devalue' library to serialize user-provided data.
2. The attacker crafts a malicious JSON or serialized object payload containing specific, repeated primitive string patterns.
3. The crafted payload is submitted to the application via an exposed network endpoint.
4. The application passes the attacker-supplied data into the 'devalue.uneval()' function.
5. The 'uneval' function fails to constrain the serialization process, resulting in quadratic expansion of the input string.
6. The application process consumes excessive CPU cycles and memory attempting to allocate the resulting large string.
7. The system becomes unresponsive or crashes due to resource exhaustion, resulting in a denial-of-service for the service users.

## Impact

Successful exploitation leads to a denial-of-service for applications relying on the vulnerable library. This can impact any service handling user input, potentially causing service outages that disrupt business operations. The attack is limited to the availability of the vulnerable system, with no documented impact on data confidentiality or integrity.

## Recommendation

Update the 'devalue' package to version 5.9.3 or later in all Node.js projects. Verify project dependencies to identify instances of the vulnerable 'devalue' package (<= 5.9.2). Monitor application logs for high memory usage or frequent service restarts associated with JSON serialization endpoints.
