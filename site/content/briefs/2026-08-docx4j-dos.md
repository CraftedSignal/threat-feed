---
title: Denial of Service in docx4j-core via Cyclic Style Inheritance
slug: 2026-08-docx4j-dos
description: The docx4j-core library is vulnerable to a stack exhaustion denial-of-service attack due to missing cycle detection in the OpenXML style resolution process.
date: "2026-08-18T00:46:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - library-vulnerability
  - java
vendors:
  - docx4j
products:
  - docx4j-core (<= 11.5.13)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A WordprocessingML document containing a cyclic style chain causes unbounded recursion and a java.lang.StackOverflowError within the property-resolution code path.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-gc95-3vw8-vg43
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53752
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade docx4j-core dependencies to patched version
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-53752
  mitigation_plan:
    - priority: immediate
      action: Isolate document parsing modules in separate worker processes
      owner: Application Security
      addresses: CVE-2026-53752
      evidence: Source notes on thread pool degradation
---

The docx4j-core library, specifically versions up to 11.5.13, contains a vulnerability in the `PropertyResolver` class that leads to a `java.lang.StackOverflowError` when parsing WordprocessingML documents. The issue stems from the library's recursive processing of the `w:basedOn` style inheritance chain without implementing cycle detection. By crafting a DOCX file with cyclic style references, such as Style A inheriting from Style B and Style B inheriting from Style A, an attacker can induce unbounded recursion. This attack pattern triggers immediate thread-stack exhaustion upon processing, which can lead to service degradation or process crashes in server-side applications that utilize docx4j for document transformation, conversion, or content extraction. Because the exploit relies on standard OOXML structure, it often bypasses conventional signature-based file scanners and endpoint security controls.

## Attack Chain

1. Attacker prepares a malicious WordprocessingML (.docx) file containing custom XML styles.
2. Within the document settings, the attacker defines Style A with a `w:basedOn` attribute pointing to Style B.
3. The attacker defines Style B with a `w:basedOn` attribute pointing back to Style A, creating a circular reference.
4. The malicious file is uploaded to a target server-side application (e.g., document converter, web portal, or email processor).
5. The target application passes the document to the vulnerable `docx4j-core` library for rendering or property extraction.
6. The `PropertyResolver` attempts to resolve effective styles by recursively calling `fillPPrStack` for the cyclic chain.
7. The Java Virtual Machine terminates the processing thread due to a `java.lang.StackOverflowError` caused by the recursion depth.
8. The application worker thread crashes, potentially leading to resource exhaustion or denial of service for other users.

## Impact

Successful exploitation results in a denial of service for the document processing pipeline. Observed impact includes the immediate termination of worker threads, which can lead to total service unavailability if the application lacks robust request isolation or thread management. This vulnerability primarily affects enterprise applications in sectors such as document management, legal tech, and collaborative platforms where untrusted DOCX file submission is a core feature. The impact is elevated in environments using containerized or serverless architectures where crashes may trigger frequent, costly restarts or cascading failures across internal dependencies.

## Recommendation

* Upgrade `docx4j-core` to a version that includes a fix for CVE-2026-53752.
* Implement input validation for uploaded files to detect cyclic `w:basedOn` references within the XML structure of the document before passing them to the rendering engine.
* Execute document conversion tasks within sandboxed or ephemeral environments that limit the impact of process crashes on the main application.
* Monitor application logs for `java.lang.StackOverflowError` exceptions associated with document parsing or transformation modules.
