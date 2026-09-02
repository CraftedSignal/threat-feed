---
title: Out-of-Bounds Write in NGINX JavaScript (njs) XML Module
slug: 2026-09-nginx-njs-xml-vuln
description: CVE-2026-78689 allows remote unauthenticated attackers to trigger an out-of-bounds heap write in the NGINX JavaScript (njs) and QuickJS (qjs) XML module via crafted namespace prefix lists.
date: "2026-09-02T17:16:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nginx:njs:*:*:*:*:*:*:*:*
  - cpe:2.3:a:quickjs:quickjs:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
  - cve-2026-78689
vendors:
  - NGINX
  - Fabrice Bellard
products:
  - njs
  - QuickJS
  - nginx-saml
cves:
  - id: CVE-2026-78689
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78689
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Review NGINX configurations for xml.exclusiveC14n() usage
      owner: Security Engineering
      due: 48h
      evidence: Source states vulnerability is reachable through xml.exclusiveC14n() method.
  mitigation_plan:
    - priority: immediate
      action: Patch njs and QuickJS to the latest version provided by vendors
      owner: IT Operations
      addresses: CVE-2026-78689
      evidence: NVD vulnerability disclosure
  gaps:
    - Missing specific patch version identifiers in brief source
---

CVE-2026-78689 is an out-of-bounds heap write vulnerability affecting the XML module of the NGINX JavaScript (njs) engine and the QuickJS (qjs) engine. The flaw is located in the xml.exclusiveC14n() method, which fails to safely process an XML namespace prefix list provided by an external source. An unauthenticated remote attacker can exploit this by passing a crafted prefix list to the method. 

When using the njs engine, the out-of-bounds write corrupts adjacent heap objects, leading to an immediate crash of the NGINX worker process. When using the QuickJS engine, the vulnerability causes memory leakage on every request, resulting in memory exhaustion. The nginx-saml reference implementation is specifically vulnerable during SAML signature verification, as it processes the InclusiveNamespaces/@PrefixList from untrusted SAML messages before verifying the digital signature. Consequently, attackers can trigger the crash or memory growth using crafted SAML Response, Assertion, LogoutRequest, or LogoutResponse packets. While remote code execution has not been observed, it remains a theoretical possibility depending on specific platform memory layout.

## Impact

The vulnerability impacts the availability of NGINX instances processing XML or SAML data. Successful exploitation leads to denial of service through repeatable worker process restarts (njs engine) or rapid worker memory growth (QuickJS engine). Because the flaw triggers before SAML signature validation, attackers do not require valid credentials or legitimate SAML tokens to impact the target service.

## Recommendation

- Identify all instances using the `nginx-saml` reference implementation and upgrade to the patched version once available.
- Review NGINX configurations for usages of `xml.exclusiveC14n()` that process untrusted XML input and implement rigorous input validation for the `PrefixList` attribute.
- Monitor NGINX error logs for recurring "worker process exited with signal" events, which may indicate crash-based denial of service attempts.
- Monitor memory usage of NGINX worker processes to detect memory exhaustion patterns indicative of QuickJS exploitation.
