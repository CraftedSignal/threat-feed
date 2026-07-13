---
title: GraphicsMagick PCD Decoder Vulnerability Allows Code Execution
slug: 2026-07-graphicsmagick-rce
description: A remote, anonymous attacker can exploit a vulnerability in the GraphicsMagick PCD decoder to potentially execute arbitrary code, corrupt memory, or cause a denial-of-service condition. This flaw could lead to compromise of the system running the affected software or disruption of its availability.
date: "2026-07-13T09:13:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - graphicsmagick
  - image-processing
  - denial-of-service
vendors:
  - GraphicsMagick
products:
  - GraphicsMagick (PCD decoder)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in GraphicsMagick ausnutzen, um möglicherweise beliebigen Code auszuführen
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: oder einen Denial-of-Service-Zustand zu verursachen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2277
---

A critical vulnerability exists within the GraphicsMagick library, specifically affecting its PCD (Kodak Photo CD) image decoder. This flaw, which can be exploited by a remote, unauthenticated attacker, poses a significant risk as it allows for arbitrary code execution, memory corruption, or a denial-of-service condition. Organizations using GraphicsMagick for image processing are at risk if they handle untrusted PCD image files. The exploitation of this vulnerability could lead to a complete compromise of the system running the affected software or severe disruption of services reliant on GraphicsMagick for image handling. This vulnerability highlights the importance of securely processing user-supplied content, particularly image files, which often serve as an attack vector for code execution and system compromise.

## Attack Chain

1. An attacker crafts a specially malformed PCD (Kodak Photo CD) image file designed to trigger the vulnerability in GraphicsMagick's decoder.
2. The attacker disseminates the malicious PCD file, potentially via email attachments, malicious websites, or by uploading it to a platform that processes images.
3. A user or an automated service on the victim's system attempts to process or convert the malicious PCD file using the vulnerable GraphicsMagick library.
4. During the parsing of the malformed PCD file, the flaw within GraphicsMagick's PCD decoder is triggered.
5. This vulnerability can lead to memory corruption, allowing the attacker to control program execution.
6. The attacker leverages this control to execute arbitrary code with the privileges of the GraphicsMagick process.
7. Alternatively, the vulnerability could cause a denial-of-service by crashing the application or service utilizing GraphicsMagick.
8. Successful code execution can result in system compromise, data exfiltration, or the installation of additional malware on the affected host.

## Impact

Successful exploitation of this GraphicsMagick vulnerability can lead to severe consequences. If arbitrary code execution is achieved, attackers can gain unauthorized control over the affected system, potentially leading to full system compromise. This could result in sensitive data exfiltration, installation of persistent backdoors, or the deployment of ransomware. In cases where memory corruption or denial-of-service occurs, critical services relying on GraphicsMagick for image processing may become unavailable, leading to significant operational disruption and financial losses. The absence of specific victim information means all organizations using GraphicsMagick and processing untrusted PCD files should consider themselves at risk.

## Recommendation

* Upgrade GraphicsMagick to a patched version that addresses this PCD decoder vulnerability as soon as a fix is available.
* Implement robust input validation and sanitization for all user-supplied image files, especially those in PCD format, before they are processed by GraphicsMagick.
* Isolate systems or applications processing untrusted image files in sandboxed environments to limit the blast radius of potential exploitation.
* Ensure that any service or application utilizing GraphicsMagick operates with the principle of least privilege.
