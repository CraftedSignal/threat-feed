---
title: Multiple Vulnerabilities in Elastic Products
slug: 2026-07-elastic-vulnerabilities
description: CERT-FR has issued an advisory detailing multiple vulnerabilities in Elastic products, including CVE-2026-42397 and CVE-2026-49092, which could allow an attacker to cause remote denial of service, compromise data confidentiality and integrity, and perform Server-Side Request Forgery (SSRF).
date: "2026-07-22T14:53:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - elastic
  - elasticsearch
  - kibana
  - data-integrity
  - data-confidentiality
  - denial-of-service
  - ssrf
vendors:
  - Elastic
products:
  - Elasticsearch 8.x (prior to 8.19.19)
  - Elasticsearch 9.4.x (prior to 9.4.4)
  - Elasticsearch 9.x (prior to 9.3.8)
  - Kibana 8.x (prior to 8.19.19)
  - Kibana 9.4.x (prior to 9.4.4)
  - Kibana 9.x (prior to 9.3.8)
cves:
  - id: CVE-2018-17245
    cvss: 9.8
    epss: 0.01295
  - id: CVE-2026-56146
    cvss: 5.4
  - id: CVE-2026-63139
    cvss: 6.5
  - id: CVE-2026-63142
    cvss: 5
  - id: CVE-2026-63143
    cvss: 4.3
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0906/
  - https://discuss.elastic.co/t/kibana-9-4-3-security-update-esa-2026-54/388553
  - https://discuss.elastic.co/t/kibana-9-3-7-9-4-4-security-update-esa-2026-55/388554
  - https://discuss.elastic.co/t/elasticsearch-8-19-18-9-3-7-9-4-4-security-update-esa-2026-56/388555
  - https://discuss.elastic.co/t/elasticsearch-8-19-18-9-3-7-9-4-4-security-update-esa-2026-57/388556
  - https://discuss.elastic.co/t/kibana-9-4-3-security-update-esa-2026-58/388557
  - https://discuss.elastic.co/t/kibana-8-19-18-9-3-7-9-4-3-security-update-esa-2026-59/388558
  - https://discuss.elastic.co/t/elasticsearch-8-19-15-9-2-9-9-3-4-security-update-esa-2026-60/388559
  - https://discuss.elastic.co/t/kibana-8-19-19-9-3-8-9-4-4-security-update-esa-2026-63/388560
  - https://discuss.elastic.co/t/elasticsearch-8-19-19-9-3-8-9-4-4-security-update-esa-2026-64/388565
  - https://discuss.elastic.co/t/kibana-9-3-8-9-4-4-security-update-esa-2026-65/388566
  - https://discuss.elastic.co/t/kibana-8-19-19-9-3-8-9-4-4-security-update-esa-2026-66/388568
  - https://discuss.elastic.co/t/kibana-9-3-8-9-4-4-security-update-esa-2026-67/388569
  - https://discuss.elastic.co/t/elasticsearch-8-19-19-9-3-8-9-4-4-security-update-esa-2026-68/388571
  - https://discuss.elastic.co/t/kibana-8-19-19-9-3-8-9-4-4-security-update-esa-2026-69/388572
  - https://discuss.elastic.co/t/kibana-9-4-4-security-update-esa-2026-70/388573
  - https://discuss.elastic.co/t/kibana-8-19-19-9-3-8-9-4-4-security-update-esa-2026-71/388574
  - https://discuss.elastic.co/t/kibana-8-19-19-9-3-8-9-4-4-security-update-esa-2026-72/388575
  - https://discuss.elastic.co/t/kibana-9-4-4-security-update-esa-2026-73/388576
  - https://discuss.elastic.co/t/elasticsearch-8-19-19-9-3-8-9-4-4-security-update-esa-2026-74/388577
  - https://www.cve.org/CVERecord?id=CVE-2018-17245
  - https://www.cve.org/CVERecord?id=CVE-2026-42397
  - https://www.cve.org/CVERecord?id=CVE-2026-49092
  - https://www.cve.org/CVERecord?id=CVE-2026-56144
  - https://www.cve.org/CVERecord?id=CVE-2026-56145
  - https://www.cve.org/CVERecord?id=CVE-2026-56146
  - https://www.cve.org/CVERecord?id=CVE-2026-56147
  - https://www.cve.org/CVERecord?id=CVE-2026-63136
  - https://www.cve.org/CVERecord?id=CVE-2026-63139
  - https://www.cve.org/CVERecord?id=CVE-2026-63140
  - https://www.cve.org/CVERecord?id=CVE-2026-63141
  - https://www.cve.org/CVERecord?id=CVE-2026-63142
  - https://www.cve.org/CVERecord?id=CVE-2026-63143
  - https://www.cve.org/CVERecord?id=CVE-2026-63144
  - https://www.cve.org/CVERecord?id=CVE-2026-63145
  - https://www.cve.org/CVERecord?id=CVE-2026-63259
  - https://www.cve.org/CVERecord?id=CVE-2026-63260
  - https://www.cve.org/CVERecord?id=CVE-2026-63261
  - https://www.cve.org/CVERecord?id=CVE-2026-63262
  - https://www.cve.org/CVERecord?id=CVE-2026-63263
---

CERT-FR has issued an advisory detailing multiple vulnerabilities discovered in Elastic products, specifically Elasticsearch and Kibana. These vulnerabilities, including CVE-2018-17245, CVE-2026-42397, CVE-2026-49092, and several others, affect various versions of Elasticsearch (8.x prior to 8.19.19, 9.4.x prior to 9.4.4, 9.x prior to 9.3.8) and Kibana (8.x prior to 8.19.19, 9.4.x prior to 9.4.4, 9.x prior to 9.3.8). If exploited, these flaws could allow an attacker to cause a remote denial of service, compromise the confidentiality and integrity of data, bypass security policies, or perform Server-Side Request Forgery (SSRF). Elastic has released security updates to address these issues, and users are urged to apply the recommended patches immediately to mitigate potential risks. This advisory was published on July 22, 2026, based on multiple Elastic security bulletins from July 21, 2026.

## Attack Chain

The provided source describes vulnerabilities and their potential impact but does not detail a specific attack chain or observed exploitation steps.

## Impact

Successful exploitation of these vulnerabilities could lead to significant operational disruption and data compromise. Attackers could launch remote denial of service attacks, rendering critical Elasticsearch and Kibana services unavailable. Furthermore, the confidentiality and integrity of data stored and processed within these systems could be compromised, leading to unauthorized access, modification, or exfiltration of sensitive information. Security policy bypasses and Server-Side Request Forgery (SSRF) vulnerabilities introduce additional vectors for attackers to escalate privileges or access internal resources, potentially broadening the scope of an attack beyond the Elastic stack itself. The advisory does not mention specific observed attacks or victim counts, but the potential for data loss and service interruption for organizations relying on Elastic products is high.

## Recommendation

* Apply the security patches provided by Elastic immediately, as detailed in the Elastic security bulletins referenced in this brief (e.g., https://discuss.elastic.co/t/kibana-9-4-3-security-update-esa-2026-54/388553), to update affected versions of Elasticsearch (e.g., to 8.19.19, 9.4.4, 9.3.8) and Kibana (e.g., to 8.19.19, 9.4.4, 9.3.8).
* Review all listed CVEs (e.g., CVE-2026-42397, CVE-2026-49092, CVE-2026-56144) for potential impact on your specific Elastic deployments and prioritize patching based on the severity and accessibility of affected components.
