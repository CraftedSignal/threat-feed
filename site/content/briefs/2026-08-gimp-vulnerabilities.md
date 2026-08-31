---
title: Multiple Vulnerabilities in GIMP Lead to DoS and Information Disclosure
slug: 2026-08-gimp-vulnerabilities
description: Multiple vulnerabilities in GIMP (CVE-2024-10332, CVE-2024-10333) allow a local attacker to cause a denial-of-service condition or perform information disclosure via malicious input files.
date: "2026-08-31T11:58:41Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:gimp:gimp:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - dos
  - information-disclosure
vendors:
  - GIMP
products:
  - GIMP
cves:
  - id: CVE-2024-10332
    cvss: 6.1
    epss: 0.00241
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3081
  - https://nvd.nist.gov/vuln/detail/CVE-2024-10332
  - https://nvd.nist.gov/vuln/detail/CVE-2024-10333
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium_term
      action: Identify GIMP installations and update to the latest available patched version.
      owner: IT Operations
      addresses: CVE-2024-10332, CVE-2024-10333
---

The GNU Image Manipulation Program (GIMP) contains multiple vulnerabilities, identified as CVE-2024-10332 and CVE-2024-10333, that impact system stability and data security. These vulnerabilities arise from insufficient validation of input files, which can be triggered when a user opens a specifically crafted image file with a vulnerable version of GIMP. An attacker with local access, or one capable of tricking a user into opening a malicious file, can leverage these flaws to induce a denial-of-service (DoS) condition, crashing the application, or to potentially perform unauthorized information disclosure by exploiting how the application handles malformed memory structures during file parsing. These issues are significant for environments where users frequently handle untrusted image data or where GIMP is used in automated processing pipelines.

## Impact

Successful exploitation of these vulnerabilities may result in an application crash (DoS) or the unintended disclosure of sensitive information stored in memory. The risk is primarily to local users who may have their GIMP environment compromised, or to automated systems configured to process external image files automatically, which could be leveraged to gain unauthorized visibility into system memory or disrupt production workflows.

## Recommendation

Prioritize the identification of GIMP installations within the enterprise environment and verify current patch status. As these vulnerabilities require the processing of specific input files, ensure that endpoint protection solutions are configured to scan image files upon arrival or before execution. Disable automated file processing or preview features in image manipulation applications where possible until updates are applied. Monitor host-based logs for recurring application crashes associated with GIMP process failures as a potential indicator of exploitation attempts.
