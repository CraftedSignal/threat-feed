---
title: Improper CRLF Validation in Netty netty-codec-smtp
slug: 2026-09-netty-crlf-validation
description: The netty-codec-smtp component in Netty suffers from insufficient CRLF validation in the SMTP command-name field, representing an incomplete remediation for CVE-2025-59419 that enables potential SMTP command injection or response splitting.
date: "2026-09-18T16:08:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:netty:netty:*:*:*:*:*:*:*:*
vendors:
  - Netty
products:
  - netty-codec-smtp (< 4.1.128.Final)
cves:
  - id: CVE-2025-59419
    epss: 0.01553
  - id: CVE-2026-93576
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93576
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development Teams
  immediate_actions:
    - action: Inventory all applications leveraging netty-codec-smtp to assess exposure.
      owner: IT Operations
      due: 72h
      evidence: Source identifier CVE-2026-93576
  mitigation_plan:
    - priority: immediate
      action: Patch netty-codec-smtp to 4.1.128.Final or later
      owner: Development Teams
      addresses: CVE-2026-93576
      evidence: NVD vulnerability entry
  gaps:
    - Lack of a known patched version number in current intelligence.
---

The netty-codec-smtp component, part of the Netty framework, contains a vulnerability where the SMTP command-name field is not properly validated against CRLF (Carriage Return Line Feed) sequences. This flaw is documented as an incomplete fix for a previously identified vulnerability, CVE-2025-59419. By failing to sanitize or reject input containing CRLF characters in the command-name field, the codec may inadvertently allow attackers to inject malicious SMTP commands or perform response splitting attacks. These protocol-level injection flaws can be leveraged to bypass security controls, manipulate mail server responses, or facilitate unauthorized communication sequences if the underlying application does not perform its own strict input validation. This vulnerability is significant for organizations utilizing Netty to build custom SMTP clients or servers, as it exposes the infrastructure to potential command manipulation despite previous attempts at remediation.

## Impact

Successful exploitation of this vulnerability in an SMTP-facing application may result in unauthorized SMTP command execution or response manipulation. Depending on the architecture, this could allow an attacker to send unauthorized emails, manipulate mail routing, or potentially gain further access by exploiting the mail server logic through injected commands. The vulnerability poses a risk to any service relying on the Netty framework for handling SMTP traffic.

## Recommendation

- Identify all applications within your environment that utilize the netty-codec-smtp library.
- Review vendor release notes and security advisories for Netty to identify the specific patch version addressing CVE-2026-93576.
- Implement mandatory library upgrades across the software development lifecycle to include the corrected version of the dependency.
- Implement additional input validation at the application layer to block CRLF sequences in command-name fields as a defense-in-depth measure while awaiting official updates.
