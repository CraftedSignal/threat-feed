---
title: Denial of Service Vulnerability in CSSOM CSSStyleDeclaration.setProperty
slug: 2026-09-cssom-dos
description: The CSSOM library up to version 0.5.0 is vulnerable to a denial of service attack via malicious CSS declarations that trigger excessive memory allocation.
date: "2026-09-18T20:07:23Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:cssom_project:cssom:*:*:*:*:*:*:*:*
products:
  - CSSOM (<= 0.5.0)
cves:
  - id: CVE-2026-93752
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93752
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Identify and inventory all applications currently using CSSOM version 0.5.0 or earlier.
      owner: Application Security
      addresses: CVE-2026-93752
      evidence: Source document confirms vulnerability in CSSOM <= 0.5.0.
  gaps:
    - Lack of vendor-provided patch version.
---

CSSOM through version 0.5.0 contains a denial of service (DoS) vulnerability located within the CSSStyleDeclaration.setProperty() method. The vulnerability arises from an improper validation of reserved property names. Specifically, the library fails to restrict the use of the property name 'length'. 

An attacker can leverage this flaw by providing a specially crafted stylesheet containing a declaration named 'length'. When processed, this declaration overwrites the library's internal counter, which leads to uncontrolled and excessive memory allocation during the cssText serialization process. This behavior results in a resource exhaustion state, causing the host process to terminate. This vulnerability impacts any application or environment utilizing CSSOM version 0.5.0 or earlier to parse or manipulate untrusted CSS input.

## Impact

Successful exploitation results in the termination of the process executing the CSSOM library. This can lead to service outages in applications that rely on CSSOM for dynamic style handling. The severity is high, as the attack vector involves the submission of malicious CSS input, which is common in web-based applications that allow user-provided stylesheets or CSS customization.

## Recommendation

Update the CSSOM library to a version later than 0.5.0 once a patched release is made available by the maintainers. If an immediate update is not possible, implement input sanitization to block any CSS declarations named 'length' from being passed to the CSSStyleDeclaration.setProperty() method.
