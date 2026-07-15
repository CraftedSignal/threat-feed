---
title: Multiple Vulnerabilities in Apache Tomcat
slug: 2026-07-multiple-vulnerabilities-apache-tomcat
description: Multiple vulnerabilities, including CVE-2026-59083 and CVE-2026-59084, have been discovered in Apache Tomcat versions 10.1.x prior to 10.1.57, 11.0.x prior to 11.0.24, and 9.0.x prior to 9.0.120, allowing an attacker to bypass security policies and cause an unspecified security issue.
date: "2026-07-15T14:34:10Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - apache
  - tomcat
  - web-server
vendors:
  - Apache
products:
  - Tomcat 10.1.x
  - Tomcat 11.0.x
  - Tomcat 9.0.x
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Elles permettent à un attaquant de provoquer un contournement de la politique de sécurité
    confidence_band: med
cves:
  - id: CVE-2026-59083
    cvss: 9.1
    epss: 0.00156
  - id: CVE-2026-59084
    cvss: 9.1
    epss: 0.00161
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0876/
  - https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.57
  - https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.120
  - https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.24
  - https://www.cve.org/CVERecord?id=CVE-2026-59083
  - https://www.cve.org/CVERecord?id=CVE-2026-59084
---

CERT-FR has issued an advisory regarding multiple vulnerabilities, specifically CVE-2026-59083 and CVE-2026-59084, identified in various versions of Apache Tomcat. These flaws affect Tomcat versions 10.1.x prior to 10.1.57, 11.0.x prior to 11.0.24, and 9.0.x prior to 9.0.120. Exploitation of these vulnerabilities could allow an attacker to bypass existing security policies and potentially lead to an additional, unspecified security compromise within the affected Apache Tomcat instances. The nature of the unspecified security issue has not been detailed by the vendor. This advisory highlights the critical need for administrators to promptly update their Tomcat installations to mitigate these risks and prevent potential unauthorized access or system degradation.

## Attack Chain

The provided intelligence describes multiple vulnerabilities but does not detail a specific attack chain or observed exploitation in the wild. The vulnerabilities are described as allowing a security policy bypass and an unspecified security issue.

## Impact

The successful exploitation of these vulnerabilities could result in attackers bypassing security controls within Apache Tomcat, potentially leading to unauthorized access, modification of data, or disruption of services. While the "unspecified security issue" prevents a precise description of the ultimate impact, any successful policy bypass often serves as a stepping stone for further, more severe attacks, including data exfiltration, system compromise, or denial of service. The widespread use of Apache Tomcat in enterprise environments means that a broad range of organizations could be affected if these vulnerabilities are left unpatched.

## Recommendation

* Patch Apache Tomcat to the latest secure versions as referenced in the vendor security bulletins to address CVE-2026-59083 and CVE-2026-59084.
* Specifically, update Apache Tomcat 10.1.x to version 10.1.57 or later, 11.0.x to 11.0.24 or later, and 9.0.x to 9.0.120 or later.
