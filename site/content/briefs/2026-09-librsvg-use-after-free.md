---
title: Use-After-Free Vulnerability in librsvg
slug: 2026-09-librsvg-use-after-free
description: A use-after-free vulnerability in librsvg (CVE-2026-96889) allows remote attackers to trigger memory corruption and potential code execution by providing specially crafted SVG documents.
date: "2026-09-23T20:44:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gnome:librsvg:*:*:*:*:*:*:*:*
vendors:
  - GNOME
products:
  - librsvg
cves:
  - id: CVE-2026-96889
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96889
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Update librsvg to the vendor-patched version
      owner: IT Operations
      addresses: CVE-2026-96889
      evidence: NVD vulnerability disclosure
---

A high-severity use-after-free vulnerability, tracked as CVE-2026-96889, has been identified in librsvg, a library used by various GNOME applications for rendering Scalable Vector Graphics (SVG). The flaw is triggered when the library processes an SVG document containing nested XML inclusions (Xincludes) with duplicate entity declarations. Due to improper memory management, the parser incorrectly deallocates an XML entity that remains in active use, resulting in a use-after-free condition. 

An attacker can exploit this by enticing a victim to open or process a maliciously crafted SVG file. Depending on the target environment and the application utilizing the library, this vulnerability could be leveraged to crash the process (denial of service) or potentially achieve arbitrary code execution within the context of the user running the affected application.

## Impact

Successful exploitation of CVE-2026-96889 can lead to application instability, service disruption, or arbitrary code execution. As librsvg is commonly integrated into image viewers, web browsers, and desktop environments, this flaw poses a risk to a wide range of Linux-based systems. Defenders should prioritize updating librsvg to the latest patched versions provided by their distribution maintainers.

## Recommendation

- Monitor Linux distribution security advisories for updated packages of librsvg.
- Patch CVE-2026-96889 on all systems where librsvg is installed as a dependency.
- Implement sandboxing or process isolation for applications that parse untrusted SVG files to limit the potential impact of code execution.
