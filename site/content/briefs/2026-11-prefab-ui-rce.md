---
brief_id: brief-2026-11-01-prefab-ui-rce
event_id: brief-2026-11-01-prefab-ui-rce
revision: 1
activity_at: "2026-11-01T18:57:08Z"
title: 'Prefab UI: Arbitrary code execution via Generative UI sandbox (CVE-2026-120338)'
slug: 2026-11-prefab-ui-rce
description: Prefab UI versions 0.14.0 through 0.20.2 contain a sandbox escape vulnerability where caller-supplied Python code executed in a Deno subprocess can access unrestricted filesystem and network permissions via the exposed Deno API.
date: "2026-11-01T18:57:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:prefab:prefab_ui:*:*:*:*:*:*:*:*
vendors:
  - Prefab
products:
  - prefab-ui (0.14.0 - 0.20.2)
cves:
  - id: CVE-2026-120338
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120338
---

The Prefab UI Generative UI feature utilizes a Deno subprocess to execute Pyodide-based Python code. In versions 0.14.0 through 0.20.2, this subprocess is initiated with unrestricted `--allow-read`, `--allow-write`, and `--allow-net` permissions. Because the Deno API remains available on the JavaScript global object, the Python sandbox can invoke privileged functions such as `Deno.readTextFileSync` and `Deno.writeTextFileSync`. An attacker providing code through the `generate_prefab_ui` tool can read/write files as the server OS user or achieve code execution persistence by creating `.pth` files in the server's virtual environment.
