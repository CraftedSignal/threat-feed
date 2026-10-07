---
title: Next.js Image Optimization SSRF Vulnerability
slug: 2026-10-nextjs-ssrf
description: Next.js versions 16.0.0 through 16.3.7 are susceptible to Server-Side Request Forgery (SSRF) when processing images from attacker-controlled remote URLs configured in remotePatterns.
date: "2026-10-07T22:49:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vercel:next.js:*:*:*:*:*:node.js:*:*
vendors:
  - Vercel
products:
  - Next.js (>= 16.0.0, < 16.3.8)
cves:
  - id: CVE-2026-94483
    cvss: 6.5
    epss: 0.00244
references:
  - https://github.com/advisories/GHSA-cjq9-62q9-8jv4
  - https://nextjs.org/docs/app/getting-started/images#remote-images
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Next.js to version 16.3.8
      owner: IT Operations
      due: 48h
      evidence: Source explicitly mandates upgrading to 16.3.8 to resolve CVE-2026-94483
  mitigation_plan:
    - priority: immediate
      action: Audit images.remotePatterns for untrusted hosts
      owner: Application Security
      addresses: CVE-2026-94483
      evidence: Source workaround instructions recommend auditing remotePatterns for hosts that may not be trusted
---

Next.js versions 16.0.0 through 16.3.7 contain a Server-Side Request Forgery (SSRF) vulnerability in the Image Optimization component (CVE-2026-94483). The vulnerability arises when the application is configured to allow remote images via the `images.remotePatterns` setting. An attacker can supply a malicious or attacker-controlled URL that is technically permitted by the allow-list but resolves to internal, private network addresses or restricted services. During the image optimization process, the server performs a request to the provided URL, allowing the attacker to probe the internal network or interact with services accessible to the Next.js server. This vulnerability does not affect applications that do not explicitly configure `images.remotePatterns`.

## Impact

Successful exploitation allows an attacker to perform unauthorized requests from the server's network context. This can lead to the exposure of internal-only metadata services (such as AWS/GCP instance metadata), internal API endpoints, or other private network resources that are otherwise unreachable from the public internet. The scope of the potential damage depends on the network architecture and the services reachable from the application server.

## Recommendation

Prioritize patching and configuration audits to mitigate SSRF risks.

- Upgrade Next.js to version 16.3.8 or later to address CVE-2026-94483.
- Audit the `images.remotePatterns` configuration in your `next.config.js` file. Remove any host patterns that are not strictly necessary or that resolve to infrastructure potentially controlled by third parties who could manipulate DNS records.
- Implement network-level egress filtering on the application server to restrict outbound connections to only known, required external endpoints, preventing the server from reaching internal RFC1918 address spaces.
