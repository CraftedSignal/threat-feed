---
brief_id: brief-2026-10-30-jspdf-lfi
event_id: brief-2026-10-30-jspdf-lfi
revision: 1
activity_at: "2026-10-30T18:59:31Z"
title: 'jsPDF: Path traversal and local file inclusion (CVE-2025-68428)'
slug: 2026-10-jspdf-lfi
description: A critical path traversal and local file inclusion vulnerability in jsPDF versions prior to 4.0.0 allows unauthenticated attackers to read arbitrary files in Node.js server-side environments.
date: "2026-10-30T18:59:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified library vulnerability scope against vendor advisory.
cpes:
  - cpe:2.3:a:jspdf:jspdf:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:parall:jspdf:*:*:*:*:*:node.js:*:*
tags:
  - path-traversal
  - local-file-inclusion
  - nodejs
  - vulnerability
  - cve-2025-68428
products:
  - jsPDF (< 4.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This flaw allows attackers to read arbitrary local files when jsPDF is used in Node.js environments and user-controlled input reaches file-loading functions.
    confidence_band: high
cves:
  - id: CVE-2025-68428
    cvss: 7.5
    epss: 0.02177
    kev_status: "false"
references:
  - https://github.com/Nurjaman2004/jsPDF-Bulk-Detector-CVE-2025-68428-
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-NURJAMAN2004-JSPDF-BULK-DETECTOR-CVE-2025-68428-
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-NURJAMAN2004-JSPDF-BULK-DETECTOR-CVE-2025-68428-&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Inventory all applications utilizing jsPDF and identify those running on Node.js.
      owner: AppSec
      due: 24h
      evidence: 'Scope: Node.js builds only (jspdf.node.js)'
  hunt_leads:
    - lead: Identify server-side endpoints processing user-controlled file paths via jsPDF library calls.
      technique_id: T1190
      data_needed:
        - Application source code analysis
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'Trace user input reaching: loadFile, addImage, addFont, html()'
  mitigation_plan:
    - priority: immediate
      action: Upgrade jsPDF to version 4.0.0 or later.
      owner: IT Operations
      addresses: CVE-2025-68428
      evidence: Upgrade to jsPDF v4.0.0+
---

CVE-2025-68428 is a critical vulnerability in the jsPDF library (versions < 4.0.0) affecting Node.js implementations. The vulnerability arises when user-controlled input is passed to server-side file-loading functions, enabling path traversal and unauthorized local file inclusion (LFI). Attackers can leverage this to read sensitive files from the server's filesystem.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary files on the server hosting the affected Node.js application, potentially leading to the disclosure of sensitive configuration files, source code, or credentials.

## Recommendation

- Upgrade jsPDF to version 4.0.0 or later immediately.
- Audit server-side code to identify instances where user-supplied input is passed to jsPDF functions like 'loadFile', 'addImage', 'addFont', or 'html()'.
- Implement strict allowlisting for file paths and parameters used in PDF generation endpoints.
- Review Node.js filesystem access permissions and ensure the process runs with the principle of least privilege.
- Use the asset discovery phase to identify where the library is in use across the environment to prioritize patching.
