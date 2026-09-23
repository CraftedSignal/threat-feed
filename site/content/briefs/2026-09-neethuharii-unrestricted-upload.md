---
title: Unrestricted File Upload Vulnerability in Neethuharii CafeManagement
slug: 2026-09-neethuharii-unrestricted-upload
description: Neethuharii CafeManagement contains an unrestricted file upload vulnerability in AddProductCode.php that allows remote attackers to upload arbitrary files via the image argument.
date: "2026-09-23T18:44:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cves:
  - id: CVE-2026-96513
    cvss: 7.3
---

A security vulnerability (CVE-2026-96513) has been identified in the Neethuharii CafeManagement software. The issue exists within the AddProductCode.php file, where the image argument fails to properly validate file types or contents, leading to an unrestricted file upload vulnerability. This vulnerability is remotely exploitable and is currently public, with proof-of-concept exploit code available. The product follows a rolling release model, meaning no specific version numbers are provided by the vendor. The vendor has not responded to disclosure attempts, leaving systems running this software potentially exposed to remote code execution through the deployment of malicious scripts.

## Impact

Successful exploitation allows a remote, unauthenticated attacker to upload arbitrary files to the server. If the application server permits the execution of these files (e.g., PHP scripts), the attacker can achieve remote code
