---
title: SiYuan Stored XSS Leads to Remote Code Execution (CVE-2026-66396)
slug: 2026-07-siyuan-xss-rce
description: SiYuan before v3.7.2 is vulnerable to stored cross-site scripting (XSS) due to improper escaping of the title-img Individual Attribute List value when rendering Gallery and Kanban cover images, allowing attackers with editor permissions to inject malicious onload handlers that execute arbitrary code in the Electron renderer with full Node.js access, leading to remote code execution.
date: "2026-07-27T16:23:41Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - xss
  - remote-code-execution
  - client-side-exploitation
  - electron
vendors:
  - SiYuan
products:
  - SiYuan (< 3.7.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers with editor permissions can inject onload handlers that execute arbitrary code in the Electron renderer with full Node.js access.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers with editor permissions can inject onload handlers that execute arbitrary code in the Electron renderer with full Node.js access when victims open affected documents.
    confidence_band: high
cves:
  - id: CVE-2026-66396
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66396
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-5rxg-wh59-mg34
  - https://www.vulncheck.com/advisories/siyuan-before-stored-xss-to-rce-via-title-img-ial
---

CVE-2026-66396 describes a critical vulnerability affecting SiYuan versions prior to v3.7.2, a popular markdown-based note-taking application. The vulnerability stems from improper input neutralization, specifically a stored cross-site scripting (XSS) flaw, where the application fails to escape user-controlled input in the `title-img Individual Attribute List` value. This occurs during the rendering of Gallery and Kanban cover images. An attacker, requiring existing editor permissions within a SiYuan instance or document, can inject malicious `onload` handlers. When a victim opens an affected document, these handlers execute arbitrary code within the Electron renderer with full Node.js access, effectively enabling remote code execution (RCE) on the victim's system. This flaw poses a significant risk as it can lead to full system compromise from a seemingly benign document interaction.

## Attack Chain

1. An attacker obtains editor permissions within a SiYuan instance or document.
2. The attacker crafts a malicious JavaScript payload containing an `onload` handler designed to execute arbitrary commands.
3. This payload is injected into the `title-img Individual Attribute List` value of a Gallery or Kanban cover image within a SiYuan document.
4. The attacker saves the modified document, thereby persisting the malicious payload.
5. A victim user opens the compromised SiYuan document containing the maliciously crafted image.
6. During the rendering of the Gallery or Kanban cover image, the SiYuan application fails to properly escape the injected `title-img Individual Attribute List` value.
7. The `onload` handler embedded in the unescaped value executes, triggering the malicious JavaScript within the Electron renderer process.
8. Due to the Electron application's full Node.js access, the malicious JavaScript achieves arbitrary code execution on the victim's system, leading to remote code execution.

## Impact

Successful exploitation of CVE-2026-66396 allows an attacker with editor permissions to achieve remote code execution on the system of any user who opens an affected SiYuan document. This can lead to complete compromise of the victim's workstation, including data exfiltration, installation of additional malware, or further lateral movement within an organization's network. While specific victim numbers are not provided, any organization using vulnerable versions of SiYuan where users share or collaborate on documents is at risk.

## Recommendation

* Patch CVE-2026-66396 immediately by upgrading SiYuan to version v3.7.2 or later on all affected systems.
* Review access controls within SiYuan instances to ensure only trusted users have editor permissions.
