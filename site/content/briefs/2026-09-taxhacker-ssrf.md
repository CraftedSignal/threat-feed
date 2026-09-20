---
title: SSRF Vulnerability in vas3k TaxHacker via Invoice PDF Renderer
slug: 2026-09-taxhacker-ssrf
description: A server-side request forgery (SSRF) vulnerability in the TaxHacker Invoice PDF Renderer allows remote attackers to perform unauthorized requests by manipulating the businessLogo argument.
date: "2026-09-20T18:22:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vas3k:taxhacker:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - web-application
  - vulnerability
vendors:
  - vas3k
products:
  - TaxHacker (<= 0.8.5)
cves:
  - id: CVE-2026-94039
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94039
rules:
  - title: Detect CVE-2026-94039 Exploitation - SSRF via businessLogo
    description: Detects exploitation attempts targeting CVE-2026-94039 where an attacker supplies a URL or internal address to the businessLogo parameter in an invoice generation request.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy webserver detection rule to flag unauthorized logo source URLs
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-94039 technical details
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound server egress to only known-good domains or block internal metadata endpoints from the web server
      owner: Network Security
      addresses: CVE-2026-94039
      evidence: SSR technique mitigation guidance
---

A server-side request forgery (SSRF) vulnerability, assigned CVE-2026-94039, has been identified in the TaxHacker application developed by vas3k in versions up to 0.8.5. The flaw is located within the `generateInvoicePDF` function inside the `/apps/invoices/actions.ts` file, specifically within the Invoice PDF Renderer component. An unauthenticated remote attacker can trigger the vulnerability by providing a crafted value to the `businessLogo` argument during the PDF generation process. Successful exploitation allows the application server to perform unauthorized outbound HTTP requests, potentially exposing internal network resources or metadata services. As of the report date, the vulnerability remains unpatched and is publicly disclosed, increasing the likelihood of exploitation attempts.

## Impact

Successful exploitation allows remote attackers to bypass network access controls, perform reconnaissance of internal infrastructure, or potentially access sensitive internal metadata and services reachable by the server. This vulnerability is applicable to any deployment of TaxHacker up to version 0.8.5.

## Recommendation

Detection engineering teams should monitor web access logs for suspicious input patterns directed at the invoice generation endpoint. Due to the lack of a vendor patch, network-level egress filtering is the most effective mitigation strategy for internal resources.
