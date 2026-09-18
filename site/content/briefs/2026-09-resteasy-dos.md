---
title: 'CVE-2026-89059: Denial of Service in RESTEasy IIOImageProvider'
slug: 2026-09-resteasy-dos
description: An unauthenticated remote attacker can trigger a denial of service in Red Hat RESTEasy by submitting a crafted image that causes excessive memory allocation within the JVM via the IIOImageProvider component.
date: "2026-09-18T12:04:53Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:redhat:resteasy:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - java
  - resteasy
vendors:
  - Red Hat
products:
  - RESTEasy
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote, unauthenticated attacker can send a small crafted image declaring enormous dimensions to trigger a very large memory allocation, exhausting the JVM heap and resulting in a denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-89059
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89059
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify all public-facing services utilizing the RESTEasy IIOImageProvider component.
      owner: IT Operations
      due: 48h
      evidence: Source states RESTEasy IIOImageProvider is the vulnerable component.
  mitigation_plan:
    - priority: immediate
      action: Apply patches provided by Red Hat to remediate CVE-2026-89059.
      owner: IT Operations
      addresses: CVE-2026-89059
      evidence: NVD vulnerability disclosure.
---

CVE-2026-89059 describes a critical vulnerability in the IIOImageProvider component of the Red Hat RESTEasy framework. The flaw stems from the application's failure to validate image dimensions and pixel counts declared within image request bodies. A remote, unauthenticated attacker can exploit this by crafting a small-sized image file that specifies extraordinarily large dimensions in its metadata. When the IIOImageProvider processes this request, it attempts to allocate memory proportional to the declared (rather than actual) size. This behavior forces the Java Virtual Machine (JVM) to perform excessive heap allocation, leading to memory exhaustion and a full application denial of service (DoS). This vulnerability is particularly dangerous in environments where RESTEasy handles public-facing image processing workflows. Defenders should prioritize auditing traffic patterns to image processing endpoints and implementing input validation constraints on image metadata.

## Impact

Successful exploitation results in a persistent denial of service of the affected application. Because the attack requires only a single crafted request to trigger the memory exhaustion event, it poses a significant risk to the availability of systems relying on RESTEasy for image handling, particularly in high-traffic or resource-constrained environments.

## Recommendation

* Monitor web server logs for suspicious requests directed at endpoints utilizing the IIOImageProvider class.
* Implement strict input validation on all image-related request bodies to enforce limits on declared pixel dimensions and file metadata.
* Evaluate the application heap memory configuration and monitor JVM memory usage patterns to detect anomalous spikes associated with image processing tasks.
* Review Red Hat security advisories for the official patched version of RESTEasy and apply updates immediately.
