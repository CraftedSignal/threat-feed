---
title: CVE-2026-86404 Arbitrary Deserialization in Red Hat JBoss EAP
slug: 2026-09-eap-artemis-deserialization
description: Red Hat JBoss Enterprise Application Platform (EAP) contains a vulnerability in its Artemis component where default deserialization configurations permit arbitrary object deserialization, potentially leading to remote code execution.
date: "2026-09-07T12:53:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:redhat:jboss_enterprise_application_platform:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - deserialization
  - rce
vendors:
  - Red Hat
products:
  - JBoss Enterprise Application Platform
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Artemis messaging component's default configuration allows arbitrary object deserialization, enabling remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1555
    technique_name: Deserialization of Untrusted Data
    evidence: The ObjectMessage.getObject() method utilizes an improperly configured ObjectInputStreamWithClassLoader that trusts all classes by default.
    confidence_band: high
cves:
  - id: CVE-2026-86404
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86404
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Patch JBoss EAP instances to the version addressing CVE-2026-86404
      owner: IT Operations
      addresses: CVE-2026-86404
      evidence: Source provided CVE identifier for a vulnerability in Artemis component
---

Red Hat JBoss Enterprise Application Platform (EAP) is affected by a critical deserialization vulnerability in its Artemis messaging component (CVE-2026-86404). The flaw resides within the `ObjectMessage.getObject()` method, which utilizes the `ObjectInputStreamWithClassLoader` class for deserialization. In default configurations, both the allow-list and block-list filters within the class remain empty. 

The security logic implemented in `checkSecurity()` and `isTrustedType()` defaults to a permissive state when the allow-list size is zero, effectively trusting all incoming serialized classes. An unauthenticated attacker capable of sending serialized objects to the Artemis component can leverage this configuration to instantiate arbitrary classes, leading to remote code execution (RCE) in the context of the application server. This vulnerability highlights the risks associated with insecure deserialization patterns in Java-based middleware and requires immediate configuration review or patching.

## Impact

Successful exploitation of CVE-2026-86404 allows an attacker to achieve remote code execution on the application server hosting the JBoss EAP instance. This may lead to full system compromise, data exfiltration, or lateral movement within the network. The scope of targeting includes any environment utilizing default configurations of the affected Artemis component in EAP.

## Recommendation

* Review JBoss EAP configuration files to identify and harden the Artemis messaging component.
* Implement strict allow-listing for deserialization filters as recommended by Red Hat to replace the default permissive behavior.
* Monitor application server logs for abnormal `java.io.ObjectInputStream` activity or unexpected class loading attempts.
* Patch the JBoss EAP instances to the latest vendor-supplied version containing the security update for CVE-2026-86404.
