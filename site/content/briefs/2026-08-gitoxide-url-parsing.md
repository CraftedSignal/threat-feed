---
title: Credential Disclosure Vulnerability in gitoxide gix-url and gix-transport Crates
slug: 2026-08-gitoxide-url-parsing
description: An improper URL parsing flaw in the gitoxide gix-url crate enables credential theft by causing the gix-transport identity guard to transmit HTTP Basic Authorization headers to unauthorized hosts via crafted redirects.
date: "2026-08-28T15:13:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gitoxide:gix-url:*:*:*:*:*:*:*:*
  - cpe:2.3:a:gitoxide:gix-transport:*:*:*:*:*:*:*:*
vendors:
  - gitoxide
products:
  - gix-url (<= 0.32.0)
  - gix-transport (<= 0.49.0)
cves:
  - id: CVE-2026-82247
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82247
action_plan:
  priority: elevated
  owners:
    - Development
    - Security Operations
  immediate_actions:
    - action: Audit software supply chain for dependency on vulnerable gitoxide crates
      owner: Development
      due: 48h
      evidence: CVE-2026-82247 disclosure
  mitigation_plan:
    - priority: immediate
      action: Upgrade gix-url to 0.37.1 and gix-transport to 0.58.1
      owner: Development
      addresses: CVE-2026-82247
      evidence: NVD release notes
---

CVE-2026-82247 describes a security vulnerability in the gitoxide Rust crates gix-url (versions <= 0.32.0) and gix-transport (versions <= 0.49.0). The vulnerability stems from a custom URL parser in gix-url that fails to correctly interpret the '?' or '#' characters as terminators for the authority component of a URL, as defined in RFC 3986. This incorrect parsing allows the gix-transport HTTP redirect identity guard (can_reuse_identity) to misidentify the target host during an HTTP redirect.

An attacker can exploit this by returning a malicious HTTP 3xx redirect with a crafted 'Location' header formatted as &lt;attacker-authority>?@&lt;original-authority>. The vulnerable identity guard incorrectly validates the target host, leading the client to reuse stored HTTP Basic Authorization credentials for the unintended attacker-controlled server. This flaw poses a high risk for any application leveraging gitoxide for Git operations that involve authenticating to remote repositories. Impacted users should update to gix-url 0.37.1 and gix-transport 0.58.1.

## Attack Chain

1. Attacker hosts a malicious Git repository or HTTP server capable of serving custom HTTP 3xx redirect responses.
2. Victim initiates a Git operation (e.g., clone, fetch, or push) using a tool built with the vulnerable gitoxide crates.
3. Victim provides valid HTTP Basic Authorization credentials for the legitimate target repository.
4. Attacker returns an HTTP redirect response with a specially crafted 'Location' header: &lt;attacker-authority>?@&lt;original-authority>.
5. The gix-url parser processes the 'Location' header but fails to terminate the authority component at the '?' character.
6. The gix-transport identity guard compares the authority based on the flawed parsing and determines it is safe to reuse the existing credentials.
7. The client library automatically includes the Authorization header containing the victim's credentials in the subsequent request to the attacker-controlled authority.
8. Attacker logs the Authorization header, successfully capturing the victim's plaintext credentials.

## Impact

Successful exploitation results in the unauthorized exposure of HTTP Basic Authorization credentials to an attacker. This potentially grants the attacker persistent access to the victim's private repositories or associated services, depending on the scope of the captured credentials. This affects any downstream software in the Rust ecosystem that integrates the gitoxide library for repository interaction.

## Recommendation

1. Identify all applications and internal tooling within the organization that utilize the gitoxide Rust crates by auditing Cargo.lock files for gix-url and gix-transport.
2. Update gix-url to version 0.37.1 or higher and gix-transport to version 0.58.1 or higher to incorporate the corrected URL parsing logic.
3. For applications where immediate patching is not possible, implement strict allowlists for trusted host destinations to prevent redirects to unauthorized domains.
4. Perform log analysis on outbound HTTP requests from build servers and automated tooling to identify suspicious redirect responses involving unconventional URL formatting.
