---
title: Copernik XML Factory XInclude Resource Resolution Vulnerability
slug: 2026-10-copernik-xml-xinclude
description: Copernik XML Factory versions prior to 0.1.2 fail to restrict XInclude resource resolution when using the stock JDK provider, enabling local file disclosure or SSRF via malicious XML inputs.
date: "2026-10-02T20:23:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:copernik:copernik-xml-factory:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - java
  - xml
vendors:
  - Copernik
products:
  - copernik-xml-factory (< 0.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An application that parses untrusted XML in this configuration can be made to resolve xi:include references, allowing an attacker to read local files or reach internal network endpoints.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xm28-xvqc-gxxg
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61586
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade copernik-xml-factory to 0.1.2
      owner: IT Operations
      due: 72h
      evidence: Applications are advised to upgrade to 0.1.2, which fixes the defect.
  mitigation_plan:
    - priority: immediate
      action: Add Apache Xerces (xercesImpl) to the classpath
      owner: IT Operations
      addresses: CVE-2026-61586
      evidence: As a workaround add Apache Xerces (xercesImpl) to the classpath so the library selects its unaffected Xerces provider.
---

Copernik XML Factory versions through 0.1.1 contain an improper restriction of XInclude resource resolution when operating on the stock JDK provider. The library provides a guarantee that XInclude resolution remains disabled; however, this guarantee fails when an application explicitly enables XInclude via `XmlFactories.newDocumentBuilderFactory()`, `XmlFactories.newSAXParserFactory()`, or `XmlFactories.harden()`. 

If an application parses untrusted XML and operates on the stock JDK provider (without Apache Xerces on the classpath), an attacker can inject `xi:include` references. This flaw permits the resolution of external resources, leading to potential local file disclosure (reading sensitive system or configuration files) or Server-Side Request Forgery (SSRF) by reaching internal network endpoints via `http` hrefs. The vulnerability does not affect applications using the Xerces provider or the Android provider. The issue is tracked as CVE-2026-61586.

## Impact

Successful exploitation allows for the unauthorized reading of local files on the server and the execution of SSRF attacks against internal network resources. This impacts Java-based applications utilizing the Copernik XML Factory library, specifically those configured to parse XML inputs from untrusted sources.

## Recommendation

- Upgrade the Copernik XML Factory library to version 0.1.2 or later to remediate CVE-2026-61586.
- Implement a temporary workaround by adding Apache Xerces (`xercesImpl`) to the application classpath, which forces the library to utilize the unaffected Xerces provider.
- Audit applications using `XmlFactories` to identify and restrict untrusted XML parsing workflows.
