---
title: Use-After-Free Vulnerability in GPAC Compositor
slug: 2026-09-gpac-uaf
description: A use-after-free vulnerability in the GPAC compositor component (CVE-2026-91087) allows remote attackers to trigger memory corruption via malicious media files.
date: "2026-09-15T07:39:39Z"
lastmod: "2026-09-16T17:52:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gpac:gpac:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
  - remote-code-execution
  - cve
vendors:
  - GPAC
products:
  - GPAC (< abi-16.24)
  - GPAC (26.07.0)
cves:
  - id: CVE-2026-91087
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91087
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92399
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade GPAC to abi-16.24
      owner: IT Operations
      due: 72h
      evidence: Upgrading to version abi-16.24 is able to resolve this issue.
  mitigation_plan:
    - priority: immediate
      action: Apply source code patch e34f4ba349d55cd1849f0bcf4cf46552732e2db7
      owner: Security Engineering
      addresses: CVE-2026-91087
      evidence: This patch is called e34f4ba349d55cd1849f0bcf4cf46552732e2db7.
updates:
  - at: "2026-09-16T17:52:13Z"
    level: L2
    summary: added coverage for GPAC (26.07.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92399
---

A use-after-free vulnerability has been identified in the GPAC multimedia framework, specifically affecting the 'gf_mo_get_od_id' function within 'compositor/media_object.c'. The flaw exists in all versions up to f1219cde. This vulnerability allows for remote exploitation when a user processes a specifically crafted malicious media file. Successful exploitation leads to memory corruption, which may result in application crashes or the potential for arbitrary code execution. As public exploit code for this vulnerability is currently available, it poses a significant risk to systems processing untrusted media content. The issue is addressed in the GPAC project by upgrading to version 'abi-16.24' or applying the patch identified by commit 'e34f4ba349d55cd1849f0bcf4cf46552732e2db7'. Organizations using GPAC as a library or standalone tool should prioritize patching.

## Impact

The vulnerability is rated with a CVSS v3.1 base score of 7.3, reflecting its high impact and remote exploitability. Successful exploitation allows for unauthorized memory access, potentially leading to service disruption through crashes or exploitation as an entry point for remote code execution. This impacts any environment utilizing GPAC to parse or render multimedia content, such as media players, streaming servers, or content transcoding pipelines.

## Recommendation

* Upgrade all instances of GPAC to version 'abi-16.24' or later.
* If upgrading is not immediately feasible, apply patch 'e34f4ba349d55cd1849f0bcf4cf46552732e2db7' to the 'compositor/media_object.c' source file.
* Monitor file processing services that ingest external media for unexpected process crashes or anomalous memory usage.
