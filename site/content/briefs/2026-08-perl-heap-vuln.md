---
title: Out-of-Bounds Memory Corruption in Perl Regular Expression Engine
slug: 2026-08-perl-heap-vuln
description: Perl versions through 5.45.1 contain a vulnerability in the S_regmatch function leading to out-of-bounds heap reads and writes during regex processing, which may allow for arbitrary code execution.
date: "2026-08-11T09:57:28Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Perl
products:
  - Perl (5.45.1)
cves:
  - id: CVE-2026-15534
    epss: 0.00196
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15534
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory all servers and containers running Perl version 5.45.1 or lower
      owner: Security Engineering
      due: 48h
      evidence: Source confirms versions through 5.45.1 are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Patch Perl to the latest secure version once vendor release is available
      owner: IT Operations
      addresses: CVE-2026-15534
      evidence: Vulnerability requires software patch
---

Perl versions through 5.45.1 contain a critical memory corruption vulnerability in the regular expression engine. The issue originates within the S_regmatch function due to an undersized superlinear cache. When processing specific, maliciously crafted regular expressions, the engine may perform out-of-bounds heap reads and writes. This flaw represents a significant risk for any application utilizing Perl to process user-supplied input via regex patterns, as it could be leveraged to crash services or achieve arbitrary code execution in the context of the Perl interpreter. Organizations utilizing Perl in web applications, CGI scripts, or data processing pipelines should prioritize updating their environment to a patched version once available.

## Impact

Successful exploitation of this vulnerability can lead to memory corruption, resulting in either a denial-of-service (process crash) or potential remote code execution. The impact is broad given Perl's prevalence in backend infrastructure, legacy web applications, and various system administration utilities.

## Recommendation

- Upgrade all Perl distributions to a version later than 5.45.1 as soon as patches are released by the Perl community.
- Review applications that utilize Perl for processing untrusted or external input via regular expressions to identify potential exposure points.
- Audit system logs for unexpected crashes of Perl-based services which may indicate failed exploitation attempts or memory instability.
