---
title: Arbitrary File Creation Vulnerability in LibreOffice
slug: 2026-09-libreoffice-file-creation
description: A vulnerability in LibreOffice (CVE-2024-7737) allows a remote attacker to create arbitrary files on a user's system by exploiting improper document feature handling.
date: "2026-09-09T12:54:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:the_document_foundation:libreoffice:*:*:*:*:*:*:*:*
vendors:
  - The Document Foundation
products:
  - LibreOffice (< 24.2.6)
cves:
  - id: CVE-2024-7737
    cvss: 8.7
    epss: 0.00388
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2023-1496
  - https://nvd.nist.gov/vuln/detail/CVE-2024-7737
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade LibreOffice to version 24.2.6 or later
      owner: IT Operations
      addresses: CVE-2024-7737
      evidence: Source advises upgrading to address the vulnerability.
---

A vulnerability identified as CVE-2024-7737 exists in LibreOffice versions prior to 24.2.6. The flaw is caused by the improper handling of specific document features within the software, which may allow an unauthenticated remote attacker to create arbitrary files on a victim's local system when a maliciously crafted document is opened. This vulnerability poses a risk of unauthorized file system write operations. Users are advised to upgrade to the latest stable version of LibreOffice to mitigate this risk.

## Impact

Successful exploitation allows for unauthorized file creation on the targeted host. Depending on the location and contents of the generated files, this could facilitate further malicious activities such as the overwriting of system configuration files, the placement of files in startup directories, or the creation of local execution artifacts. The vulnerability affects users on Windows, Linux, and macOS platforms.

## Recommendation

Update all LibreOffice installations to version 24.2.6 or later to address the vulnerability documented in CVE-2024-7737.
