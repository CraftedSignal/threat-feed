---
title: Server-Side Template Injection in NetBox via Custom Links
slug: 2026-10-netbox-ssti
description: Authenticated users can exploit an SSTI vulnerability in NetBox versions 2.9.5 through 4.6.x to exfiltrate session cookies and API tokens by injecting malicious Django HttpRequest references into Jinja2 templates.
date: "2026-10-06T20:57:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cves:
  - id: CVE-2026-104073
    cvss: 7.6
---

NetBox versions 2.9.5 through 4.6.x are affected by a server-side template injection (SSTI) vulnerability, identified as CVE-2026-104073. The flaw exists because the raw Django HttpRequest object is inadvertently exposed to the Jinja2 template context used by the custom links feature. This vulnerability allows an authenticated user with the "Can add custom links" permission to inject malicious syntax that bypasses the clean_html sanitizer. By crafting a custom link that references sensitive request attributes such as 'sessionid' or API tokens, an attacker can force a victim's browser to send these credentials to an attacker-controlled external host via an image request. This flaw poses a significant risk to organizational infrastructure, as successful exploitation can lead to full account takeover, including administrative accounts, allowing attackers to manipulate network inventory data and potentially pivot within the internal network.

## Attack Chain

1. Attacker gains access to a low-privileged account with the "Can add custom links" permission.
2. Attacker navigates to the NetBox interface to create a new custom link object.
3. Attacker inputs a malicious Jinja2 template string into the link configuration, utilizing the exposed 'request' object (e.g., {{ request.COOKIES['sessionid'] }}).
4. The malicious template is saved as a custom link associated with a specific NetBox object.
5. A privileged user (e.g., administrator) views the object containing the malicious custom link in their browser.
6. The server renders the template, embedding the victim's session cookie or API token into the image source URL.
7. The victim's browser automatically triggers an HTTP request to the attacker-controlled server containing the exfiltrated sensitive data.
8. Attacker captures the session token from the incoming web server logs and performs account takeover.

## Impact
