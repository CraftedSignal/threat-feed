---
title: Denial of Service Vulnerability in libexpat Unicode Processing
slug: 2026-08-libexpat-oob-read
description: An out-of-bounds read and infinite loop vulnerability in libexpat versions prior to 2.8.3, triggered by improper Unicode surrogate pair handling, allows for denial-of-service via malformed XML.
date: "2026-08-11T12:01:55Z"
type: advisory
types:
  - advisory
severities:
  - low
products:
  - libexpat (< 2.8.3)
cves:
  - id: CVE-2026-72522
    cvss: 6.2
    epss: 0.00153
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72522
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory software assets using libexpat to identify systems requiring updates to version 2.8.3.
      owner: Security Engineering
      due: 48h
      evidence: CVE-2026-72522 remediation requires updating libexpat to 2.8.3
  mitigation_plan:
    - priority: immediate
      action: Update libexpat library to version 2.8.3 or later.
      owner: IT Operations
      addresses: CVE-2026-72522
      evidence: Vendor recommendation for CVE-2026-72522
---

CVE-2026-72522 identifies a critical flaw in the libexpat XML parsing library occurring in versions prior to 2.8.3. The vulnerability manifests during the processing of Unicode characters within the library's *_toUtf16 functions. Due to the failure to correctly distinguish between high and low surrogate pairs, the parser experiences an out-of-bounds read and enters an infinite loop when encountering malformed surrogate sequences in an input XML document. This behavior effectively leads to a denial-of-service (DoS) condition on any application utilizing the affected version of libexpat to process external or untrusted XML data. As libexpat is a widely used foundational component in many software ecosystems, the scope of potential impact is broad, depending on the exposure of the host application to unauthenticated XML input.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, where the service or application processing the XML input becomes unresponsive due to the infinite loop. This can lead to service outages and resource exhaustion on affected systems. The vulnerability affects any software product that statically or dynamically links against libexpat versions earlier than 2.8.3.

## Recommendation

Prioritize the identification of all applications and software stacks within the environment that include the libexpat library. Upgrade all instances of libexpat to version 2.8.3 or later to remediate CVE-2026-72522. For systems where an immediate library update is not feasible, restrict the ingestion of XML data from untrusted sources to minimize the risk of triggering the parsing flaw.
