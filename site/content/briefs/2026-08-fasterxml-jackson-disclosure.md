---
title: FasterXML Jackson-databind Information Disclosure Vulnerability
slug: 2026-08-fasterxml-jackson-disclosure
description: A vulnerability in FasterXML Jackson-databind identified as CVE-2024-42572 allows a remote unauthenticated attacker to exploit polymorphic type handling for information disclosure.
date: "2026-08-25T09:58:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:arajajyothibabu:school_management_system:*:*:*:*:*:*:*:*
vendors:
  - FasterXML
products:
  - Jackson-databind
cves:
  - id: CVE-2024-42572
    cvss: 9.8
    epss: 0.006
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2988
  - https://nvd.nist.gov/vuln/detail/CVE-2024-42572
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all Java applications utilizing Jackson-databind and update to the latest version.
      owner: Application Security
      due: 72h
      evidence: CVE-2024-42572 patch availability
  mitigation_plan:
    - priority: short_term
      action: Review Jackson-databind configurations to restrict polymorphic type handling.
      owner: Application Security
      addresses: CVE-2024-42572
      evidence: General mitigation for Jackson type handling vulnerabilities
---

FasterXML has disclosed a vulnerability, tracked as CVE-2024-42572, affecting the Jackson-databind library. The vulnerability allows a remote, unauthenticated attacker to cause an information disclosure through the manipulation of polymorphic type handling mechanisms. This issue typically occurs when the library is configured to process untrusted JSON input that leverages specific class types to leak information from the application environment. Defenders should review applications utilizing Jackson-databind to ensure they are updated to a non-vulnerable version, as the library is a pervasive component in Java-based web applications and API frameworks.

## Impact

Successful exploitation could result in the disclosure of sensitive application data, which may include memory contents, environment variables, or other sensitive configuration details accessible to the application process. While the exact scope of affected environments depends on specific application implementation, the widespread use of Jackson-databind in enterprise Java applications makes this a relevant concern for security teams maintaining server-side infrastructure.

## Recommendation

- Identify applications using vulnerable versions of Jackson-databind through software composition analysis (SCA) or build-time dependency manifests.
- Upgrade Jackson-databind to the latest patched version provided by the FasterXML project to address CVE-2024-42572.
- Validate that Jackson polymorphic type handling features (enableDefaultTyping) are disabled or restricted to a strict allowlist of classes.
