---
title: OpenMage LTS Phar Deserialization RCE
slug: 2024-01-openmage-phar-deserialization
description: A remote code execution vulnerability exists in OpenMage LTS versions prior to 20.16.1 due to Phar deserialization, where an attacker can upload a malicious phar file disguised as an image and trigger deserialization via functions like `getimagesize()`, `file_exists()`, or `is_readable()` when processing `phar://` stream wrapper paths, leading to arbitrary code execution.
date: "2026-04-21T14:32:48Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - phar deserialization
  - remote code execution
  - OpenMage LTS
  - Magento 1.x
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-fg79-cr9c-7369
  - https://hackerone.com/reports/3482926
rules:
  - title: Detect Phar Stream Wrapper Access
    description: Detects attempts to access files using the phar:// stream wrapper, which can indicate a phar deserialization attack.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect PHP file upload with Phar signature
    description: Detects PHP file uploads with a Phar signature, which may indicate a malicious upload.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenMage LTS versions prior to 20.16.1 are vulnerable to remote code execution due to insecure handling of PHP archives (phar) and the `phar://` stream wrapper. The vulnerability stems from the usage of functions like `getimagesize()`, `file_exists()`, and `is_readable()` with potentially controllable file paths in image validation and media handling. An attacker can exploit this by uploading a specially crafted polyglot file (a valid image that is also a valid phar archive) and then triggering the vulnerable functions to access it using the `phar://` protocol, resulting in the deserialization of malicious code. This issue affects any versions derived from Magento 1.x with the vulnerable code paths in `app/code/core/Mage/Core/Model/File/Validator/Image.php`, `app/code/core/Mage/Cms/Model/Wysiwyg/Images/Storage.php`, and `lib/Varien/Image.php`.

## Attack Chain

1.  The attacker crafts a polyglot file that is both a valid image (e.g., JPEG) and a valid PHP archive (phar).
2.  The malicious phar archive contains serialized PHP objects designed to execute arbitrary code when deserialized.
3.  The attacker uploads the polyglot file to the OpenMage LTS server through a vulnerable endpoint, such as product images, CMS media, or file import functionality.
4.  The application stores the uploaded file in a publicly accessible directory.
5.  The attacker triggers the vulnerable application logic in `app/code/core/Mage/Core/Model/File/Validator/Image.php` (line 72), `app/code/core/Mage/Cms/Model/Wysiwyg/Images/Storage.php` (line 137) or `lib/Varien/Image.php` (line 71), causing the application to use `getimagesize()` or similar functions on the uploaded file with the `phar://` stream wrapper.
6.  PHP attempts to read the file using the `phar://` wrapper, which triggers the deserialization of the malicious metadata contained within the phar archive.
7.  The deserialization process instantiates the malicious PHP objects, executing the attacker's code.
8.  The attacker achieves remote code execution on the server, allowing them to compromise the system, install malware, or exfiltrate data.

## Impact

Successful exploitation allows an attacker to execute arbitrary code on the OpenMage LTS server. This can lead to complete system compromise, data theft, defacement of the website, or the installation of malware. Given the potential for unauthenticated file uploads, the impact is significant, with potential widespread compromise affecting all versions of OpenMage LTS prior to 20.16.1. The vulnerability exists in core Magento 1.x code, so all derived products are affected.

## Recommendation

*   Upgrade OpenMage LTS to version 20.16.1 or later to patch the vulnerability.
*   Implement the recommended code fix by blocking `phar://` paths before passing to vulnerable functions like `getimagesize()` in the affected files: `app/code/core/Mage/Core/Model/File/Validator/Image.php`, `app/code/core/Mage/Cms/Model/Wysiwyg/Images/Storage.php`, and `lib/Varien/Image.php`.
*   Deploy the Sigma rule to detect attempts to access files using the `phar://` stream wrapper (see rule "Detect Phar Stream Wrapper Access").
*   If upgrading is not immediately possible, disable the `phar://` stream wrapper in the `php.ini` file.
*   Implement strict upload validation beyond file extension checks to prevent the upload of polyglot files.
