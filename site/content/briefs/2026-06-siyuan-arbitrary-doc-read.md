---
title: SiYuan Arbitrary Document Reading Vulnerability in Publishing Service
slug: 2026-06-siyuan-arbitrary-doc-read
description: SiYuan is vulnerable to arbitrary document reading via the publishing service, allowing attackers to retrieve document IDs and view the content of all documents, including encrypted or prohibited ones, by exploiting the `/api/file/readDir` and `/api/block/getChildBlocks` interfaces.
date: "2026-03-25T19:37:18Z"
severities:
  - critical
tags:
  - siyuan
  - arbitrary-document-access
  - vulnerability
  - webserver
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
references:
  - https://github.com/advisories/GHSA-34xj-66v3-6j83
rules:
  - title: SiYuan Arbitrary Document Access via getChildBlocks
    description: Detects potential exploitation of the SiYuan arbitrary document access vulnerability by monitoring requests to the /api/block/getChildBlocks endpoint.
    platform: sigma
    severity: critical
    tactics:
      - information_gathering
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
  - title: SiYuan Document ID Enumeration via readDir
    description: Detects potential document ID enumeration attempts by monitoring requests to the /api/file/readDir endpoint.
    platform: sigma
    severity: medium
    tactics:
      - information_gathering
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SiYuan, a note-taking application, is susceptible to an arbitrary document reading vulnerability within its publishing service. This flaw allows an unauthenticated attacker to bypass access controls and retrieve the content of any document, regardless of encryption or access restrictions. The vulnerability stems from inadequate authorization checks when accessing document content through specific API endpoints. The issue was reported on March 25, 2026, and is tracked as CVE-2026-33669. The…
