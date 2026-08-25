---
title: CVE-2026-78637 Argument Injection in Fdawgs node-poppler
slug: 2026-08-node-poppler-argument-injection
description: An argument injection vulnerability in the node-poppler package allows remote attackers to inject malicious command-line arguments via the file_path parameter.
date: "2026-08-25T06:05:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - vulnerability
  - argument-injection
vendors:
  - Fdawgs
products:
  - node-poppler
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: Performing a manipulation of the argument file_path results in argument injection.
    confidence_band: high
cves:
  - id: CVE-2026-78637
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78637
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Update node-poppler to the patched version
      owner: Development
      due: 48h
      evidence: Source recommends applying a patch to fix the issue.
  mitigation_plan:
    - priority: immediate
      action: Validate and sanitize user input for file_path parameters
      owner: Development
      addresses: CVE-2026-78637
      evidence: Vulnerability caused by improper handling of the file_path argument.
---

CVE-2026-78637 is an argument injection vulnerability affecting Fdawgs node-poppler versions up to 9.1.2 and 10.0.1. The flaw exists within the Argument Injection Handler logic located in src/index.js, impacting multiple functions including pdfInfo, pdfToText, pdfToCairo, pdfToPpm, pdfImages, pdfToHtml, pdfToPs, pdfFonts, pdfDetach, pdfAttach, pdfSeparate, and pdfUnite. By manipulating the file_path argument provided to these functions, a remote attacker can influence the underlying system command execution. This vulnerability is critical for applications that pass user-supplied file paths to these node-poppler methods, as it enables the execution of arbitrary command-line flags. Defenders should prioritize updating to the patched version, as identified by commit hash db6e3f79d3beb20601be7e59669c39811ae3c330.

## Impact

Successful exploitation allows for argument injection, which may result in unauthorized command execution or the modification of standard command behavior. This affects any application utilizing node-poppler to process user-provided file paths.

## Recommendation

- Upgrade the node-poppler dependency to a version containing the patch referenced in commit db6e3f79d3beb20601be7e59669c39811ae3c330.
- Audit applications utilizing node-poppler to ensure that all inputs passed to file_path parameters are strictly validated against a whitelist of expected formats before being processed.
- Apply the patch for CVE-2026-78637 across all affected environments immediately.
