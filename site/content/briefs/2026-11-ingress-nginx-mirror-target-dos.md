---
brief_id: brief-2026-11-05-ingress-nginx-mirror-target-dos
event_id: brief-2026-11-05-ingress-nginx-mirror-target-dos
revision: 1
activity_at: "2026-11-05T20:26:35Z"
title: 'ingress-nginx: Denial of service and traffic redirection (CVE-2026-116472)'
slug: 2026-11-ingress-nginx-mirror-target-dos
description: A security issue in ingress-nginx allows users with permission to create an Ingress to cause a denial of service of the ingress-nginx data plane or potentially redirect traffic from other Ingresses. Kubernetes clusters are only affected if using ingress-nginx.
date: "2026-11-05T20:26:35Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:kubernetes:ingress_nginx:*:*:*:*:*:*:*:*
tags:
  - kubernetes
  - ingress-nginx
  - denial-of-service
  - vulnerability
vendors:
  - Kubernetes
products:
  - ingress-nginx
cves:
  - id: CVE-2026-116472
    cvss: 2.7
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/523
---

A security issue was discovered in ingress-nginx. A user with permission to create an Ingress may be able to cause a denial of service of the ingress-nginx data plane or potentially redirect traffic from other Ingresses. Kubernetes will not be issuing a fix for this CVE because ingress-nginx maintenance ended in March 2026.
