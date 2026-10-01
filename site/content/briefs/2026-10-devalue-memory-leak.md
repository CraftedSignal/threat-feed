---
title: Information Disclosure via Improper Buffer Serialization in devalue
slug: 2026-10-devalue-memory-leak
description: The devalue library improperly serializes Node.js Buffer objects, exposing up to 64 KB of process-wide memory to end users in SSR environments via CVE-2026-92708.
date: "2026-10-01T20:22:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:devalue_project:devalue:*:*:*:*:*:node.js:*:*
tags:
  - information-disclosure
  - supply-chain
  - npm
  - ssr
products:
  - devalue (5.1.0 - 5.9.2)
cves:
  - id: CVE-2026-92708
    cvss: 7.5
    epss: 0.00725
references:
  - https://github.com/advisories/GHSA-j22f-vq7h-c4qm
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-92708
action_plan:
  priority: elevated
  owners:
    - Development Team
    - Security Operations
  immediate_actions:
    - action: Audit codebases for 'devalue' usage in SSR state serialization and apply the suggested Uint8Array conversion.
      owner: Development Team
      due: 48h
      evidence: Source workaround recommendation
  mitigation_plan:
    - priority: immediate
      action: Upgrade devalue to 5.9.3 or later
      owner: Development Team
      addresses: CVE-2026-92708
      evidence: Source advisory
---

The 'devalue' npm package (versions 5.1.0 through 5.9.2) contains an information disclosure vulnerability, identified as CVE-2026-92708, resulting from incorrect serialization of Node.js Buffer objects. When using the 'stringify' or 'uneval' functions, the library serializes the underlying process-wide memory backing the Buffer rather than the specific view intended.

Because Node.js utilizes a shared pool for Buffer memory, this vulnerability allows for the leakage of up to 64 KB of unrelated process memory into serialized output. In the context of Server-Side Rendering (SSR) frameworks such as SvelteKit or Nuxt, this behavior can be exploited by an unauthenticated party to extract sensitive data belonging to other users. This includes bytes from concurrent requests, such as HTTP request bodies or Authorization headers, which are subsequently embedded into server-rendered HTML. Unlike other vulnerabilities in the library, this issue occurs during serialization and is not mitigated by existing prototype pollution or Denial of Service guards, potentially impacting every SSR render involving Buffer objects.

## Impact

The vulnerability poses a severe risk of data exfiltration in web applications utilizing 'devalue' for server-side state serialization. By repeatedly triggering server-side renders that include small Buffers, an attacker can harvest sensitive data from the application's process memory. This exposure includes authentication tokens, user-specific request data, and other sensitive information from concurrent traffic. Successful exploitation leads to unauthorized data access and potential account takeover or business logic compromise.

## Recommendation

Prioritize remediation for all applications using 'devalue' for SSR state handling.

* Upgrade to a version of 'devalue' that addresses the memory serialization behavior.
* If an immediate upgrade is unavailable, manually convert all Node.js Buffer objects to Uint8Array instances before passing them to 'devalue.stringify()' or 'devalue.uneval()' as a temporary mitigation.
* Audit SSR logic in SvelteKit and Nuxt applications to identify instances where Buffer objects are included in serialized state.
