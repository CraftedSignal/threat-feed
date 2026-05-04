---
title: livewire-markdown-editor Arbitrary File Upload Vulnerability
slug: 2024-01-02-livewire-markdown-editor-upload
description: The livewire-markdown-editor versions before v1.3 contain an arbitrary file upload vulnerability in the MarkdownEditor::updatedAttachments() Livewire handler, allowing authenticated users to upload any file type, potentially leading to stored XSS, phishing, malware distribution, and markdown injection.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-file-upload
  - stored-xss
  - vulnerability
vendors:
  - DigitalOcean
  - Cloudflare
  - Scaleway
products:
  - mckenziearts/livewire-markdown-editor (< 1.3)
  - DigitalOcean Spaces
  - Cloudflare R2
  - Scaleway Object Storage
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-gxxh-8vcj-w2mh
  - https://cwe.mitre.org/data/definitions/434.html
  - https://cwe.mitre.org/data/definitions/79.html
rules:
  - title: Detect Suspicious File Uploads to Storage Domain
    description: Detects requests to the storage domain with unusual file extensions indicative of potential exploitation of the arbitrary file upload vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Markdown Injection via Filenames in Web Logs
    description: Detects potential markdown injection attempts by analyzing web server logs for specific markdown characters in uploaded filenames.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Versions of `mckenziearts/livewire-markdown-editor` prior to v1.3 are vulnerable to arbitrary file upload via the `MarkdownEditor::updatedAttachments()` Livewire handler. This handler lacks server-side validation for file types, extensions, and content. An authenticated user with access to a page embedding the markdown editor can upload malicious files (e.g., `.html`, `.svg`, `.js`) to the disk configured by `livewire-markdown-editor.disk`. If this disk is a public cloud storage bucket (S3, DigitalOcean Spaces, Cloudflare R2, Scaleway Object Storage), the uploaded files are publicly accessible with a guessed `Content-Type` header. This vulnerability allows attackers to perform stored XSS, host phishing pages, distribute malware, and inject malicious markdown. A real-world exploitation was observed in production.

## Attack Chain

1. An attacker gains access to an application using a vulnerable version of `mckenziearts/livewire-markdown-editor`.
2. The attacker navigates to a page embedding the `<livewire:markdown-editor>` component.
3. The attacker uses the file upload functionality of the editor to upload a malicious file, such as a `.html` or `.svg` file containing XSS payloads.
4. The `MarkdownEditor::updatedAttachments()` Livewire handler processes the uploaded file without proper validation.
5. The handler stores the file on the disk configured by `livewire-markdown-editor.disk` (e.g., a public cloud bucket like S3, DigitalOcean Spaces, Cloudflare R2, Scaleway Object Storage).
6. The uploaded file becomes publicly accessible on the storage domain.
7. A user visits the URL of the uploaded malicious file, triggering the XSS payload or accessing the phishing page.
8. The attacker achieves their objective, such as stealing user credentials, redirecting users to malicious websites, or compromising the application's integrity.

## Impact

Successful exploitation of this vulnerability can lead to several critical impacts. Stored XSS on the storage domain can allow attackers to steal user credentials or perform other malicious actions in the context of the application. Phishing pages hosted on the application's storage domain can trick users into revealing sensitive information. Malware distribution from a domain users trust can lead to widespread infections. Additionally, markdown injection via crafted filenames can compromise the integrity of the editor's output. A real-world exploitation of this vulnerability was observed in production on a community platform using this package.

## Recommendation

*   Upgrade to `mckenziearts/livewire-markdown-editor` v1.3 or later to patch the vulnerability.
*   If immediate upgrading is not feasible, disable the upload UI on every instance of the editor by passing `:show-upload="false"`. This prevents the vulnerable code path from being reached.
*   Monitor web server logs (category `webserver`, product `linux`) for requests to the storage domain for unusual file extensions like `.html`, `.svg`, `.js`, `.php`, or `.exe`, which could indicate attempted exploitation.
*   Implement the file upload detection rule to identify potentially malicious file uploads to the storage domain.
