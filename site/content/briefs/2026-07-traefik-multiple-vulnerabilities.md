---
title: Multiple Security Policy Bypass Vulnerabilities in Traefik Edge Router
slug: 2026-07-traefik-multiple-vulnerabilities
description: Multiple vulnerabilities have been discovered in Traefik, affecting versions 3.6.x prior to 3.6.23, 3.7.x prior to 3.7.7, and versions prior to 2.11.52, which allow an attacker to bypass security policies, potentially leading to unauthorized access or actions.
date: "2026-07-09T14:26:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - policy-bypass
  - Traefik
  - edge-router
vendors:
  - Traefik
products:
  - Traefik < 3.6.23
  - Traefik < 3.7.7
  - Traefik < 2.11.52
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0851/
  - https://github.com/traefik/traefik/security/advisories/GHSA-42cj-m3vj-89wv
  - https://github.com/traefik/traefik/security/advisories/GHSA-cxjq-mrr5-89rv
  - https://github.com/traefik/traefik/security/advisories/GHSA-qq9q-x9w4-chhj
iocs:
  - type: url
    value: https://github.com/traefik/traefik/security/advisories/GHSA-42cj-m3vj-89wv
  - type: url
    value: https://github.com/traefik/traefik/security/advisories/GHSA-cxjq-mrr5-89rv
  - type: url
    value: https://github.com/traefik/traefik/security/advisories/GHSA-qq9q-x9w4-chhj
ioc_counts:
  url: 3
---

The French national cybersecurity agency, ANSSI CERT-FR, issued an advisory on July 9, 2026, detailing multiple security vulnerabilities in Traefik, an open-source Edge Router. These flaws impact Traefik versions 3.6.x prior to 3.6.23, versions 3.7.x prior to 3.7.7, and all versions prior to 2.11.52. The vulnerabilities allow an attacker to bypass security policies implemented by Traefik, potentially leading to unauthorized access, exposure of sensitive internal services, or manipulation of traffic. Defenders should prioritize patching these versions to prevent exploitation and maintain the integrity of their network edge. These vulnerabilities could expose an organization's internal infrastructure if not addressed promptly.

## Impact

The identified vulnerabilities enable attackers to circumvent Traefik's security policy. This could result in unauthorized access to internal services that should otherwise be protected, potentially exposing sensitive applications or data. Successful exploitation could lead to data breaches, unauthorized system modifications, or further network penetration by hostile actors. While specific victim counts or targeted sectors were not detailed, any organization utilizing affected Traefik versions is at risk of exposure if patches are not applied.

## Recommendation

- Apply the latest security patches provided by the vendor to all affected Traefik versions immediately.
- Consult the Traefik security advisories for detailed patching instructions at `https://github.com/traefik/traefik/security/advisories/GHSA-42cj-m3vj-89wv`, `https://github.com/traefik/traefik/security/advisories/GHSA-cxjq-mrr5-89rv`, and `https://github.com/traefik/traefik/security/advisories/GHSA-qq9q-x9w4-chhj`.
