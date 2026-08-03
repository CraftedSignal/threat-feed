---
title: Path Traversal Vulnerability in Grav CMS ImageMedium Class
slug: 2026-08-grav-cms-traversal
description: Grav CMS 2.0.10 is vulnerable to path traversal in the ImageMedium::watermark() method, allowing unauthenticated attackers to disclose arbitrary image files by traversing outside the media sandbox.
date: "2026-08-03T16:06:24Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Grav CMS
products:
  - Grav CMS (2.0.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Grav CMS 2.0.10 contains a path traversal vulnerability in ImageMedium::watermark() allowing arbitrary image files outside Grav's media sandbox to be disclosed.
    confidence_band: high
cves:
  - id: CVE-2026-69089
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69089
rules:
  - title: Detect CVE-2026-69089 Exploitation Attempt
    description: Detects path traversal sequences in HTTP requests targeting image parameters in Grav CMS.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade all instances of Grav CMS to the latest patched version.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-69089
---

Grav CMS version 2.0.10 contains a path traversal vulnerability in the ImageMedium::watermark() method. The vulnerability arises because the application passes an unsanitized image argument to the RocketTheme\Toolbox\ResourceLocator\UniformResourceLocator::findResource() method. The implementation of the file:// scheme branch fails to perform a proper realpath or containment check, relying only on lexical collapse of '..' path segments. 

An attacker can exploit this by crafting malicious Markdown image syntax that includes path traversal sequences. This allows the application to resolve and process files located outside of the designated media directory. The system subsequently composites the unauthorized file into a carrier image, caches the resulting file, and serves it through a public-facing, unauthenticated URL. This leads to the unauthorized disclosure of sensitive image data residing on the web server to remote anonymous visitors.

## Attack Chain

1. Attacker identifies a Grav CMS instance running version 2.0.10.
2. Attacker authors a malicious Markdown document containing a crafted image tag.
3. The image tag includes directory traversal sequences (e.g., ../../) in the watermark parameter.
4. The ImageMedium::watermark() method receives the malicious payload.
5. The input is passed to UniformResourceLocator::findResource(), which fails to validate the traversal path.
6. The application resolves the path to an image file outside the intended web root or media sandbox.
7. The server processes and composites the unauthorized image into a new file.
8. The final file is cached and exposed via a public URL, allowing the attacker to download the sensitive content.

## Impact

Successful exploitation allows for the unauthenticated disclosure of any image file accessible to the web server process. This could result in the exposure of private administrative images, sensitive site metadata, or other assets not intended for public consumption. Given the CVSS score of 7.5, this poses a high risk to data confidentiality for affected web platforms.

## Recommendation

Prioritize the identification of all internet-facing instances of Grav CMS version 2.0.10 and upgrade to the latest patched version immediately. Monitor web server access logs for anomalous requests containing path traversal sequences (e.g., ../) targeting image processing parameters or Markdown-related endpoints. Ensure that web server file system permissions follow the principle of least privilege to restrict the web user's access to files outside of the defined document root.
