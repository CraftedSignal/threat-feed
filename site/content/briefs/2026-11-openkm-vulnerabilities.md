---
brief_id: brief-2026-11-16-openkm-vulnerabilities
event_id: brief-2026-11-16-openkm-vulnerabilities
revision: 1
activity_at: "2026-11-16T22:36:20Z"
title: OpenKM Community Edition XXE and Unauthorized Workflow Execution
slug: 2026-11-openkm-vulnerabilities
description: OpenKM Community Edition contains two vulnerabilities (CVE-2026-112181, CVE-2026-112182) allowing authenticated users with ROLE_USER to perform SSRF, local file reading, and remote code execution.
date: "2026-11-16T22:36:20Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:openkm:community_edition:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CD25502A-BCB8-58C6-8298-255D2D5680B4&utm_source=rss&utm_medium=rss
tags:
  - cve
  - xxe
  - ssrf
  - rce
  - web-application
vendors:
  - OpenKM
products:
  - OpenKM Community Edition
cves:
  - id: CVE-2026-112181
    epss: 0.00427
    kev_status: "false"
  - id: CVE-2026-112182
    epss: 0.00368
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2026-112181
  - https://cveawg.mitre.org/api/cve/CVE-2026-112182
  - https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-openkm-community-edition
  - https://sploitus.com/exploit?id=CD25502A-BCB8-58C6-8298-255D2D5680B4&utm_source=rss&utm_medium=rss
---

## Overview
OpenKM Community Edition is affected by two vulnerabilities. CVE-2026-112181 is an XML External Entity (XXE) vulnerability in FormUtils/LocalEntityResolver, allowing SSRF (in versions 6.3.x) or local file read and internal resource access (in version 7.0.3). CVE-2026-112182 is an authorization vulnerability in the REST endpoints 'registerProcessDefinition' and 'runProcessDefinition', allowing authenticated users with ROLE_USER to register and execute process definitions containing BeanShell scripts, resulting in remote code execution with service privileges.

## Attack Chain
An attacker requires the ROLE_USER role to interact with the vulnerable REST API endpoints. For CVE-2026-112181, an authenticated attacker exploits the flaw via a REST request. For CVE-2026-112182, the attacker registers and executes a process definition containing malicious code to execute OS commands.

## Impact
Successful exploitation of CVE-2026-112181 results in SSRF or local file reading. Exploitation of CVE-2026-112182 results in arbitrary code execution on the server. The process may run with root privileges in default Docker configurations.

## Recommendation
- Upgrade: For CVE-2026-112181, upgrade to 7.0.4. For CVE-2026-112182, update to 6.3.14 when available. Version 6.3.14 is also pending for CVE-2026-112181.
- Mitigation: Restrict non-administrator access to /OpenKM/services/rest/workflow/* and /OpenKM/services/OKMWorkflow via a reverse proxy or firewall. Block the entire /OpenKM/services/* directory if not in use.
