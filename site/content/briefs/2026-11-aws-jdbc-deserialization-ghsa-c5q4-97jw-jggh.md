---
brief_id: brief-2026-11-17-aws-jdbc-deserialization-ghsa-c5q4-97jw-jggh
event_id: brief-2026-11-17-aws-jdbc-deserialization-ghsa-c5q4-97jw-jggh
revision: 1
activity_at: "2026-11-17T21:04:53Z"
title: 'AWS Advanced JDBC Wrapper: Java Deserialization Remote Code Execution (CVE-2026-14265)'
slug: 2026-11-aws-jdbc-deserialization-ghsa-c5q4-97jw-jggh
description: A Java deserialization vulnerability in the RemoteQueryCachePlugin of the AWS Advanced JDBC Wrapper allows remote code execution when an actor with write access to a shared Redis or Valkey cache injects a crafted serialized object.
date: "2026-11-17T21:04:53Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:amazon:advanced_jdbc_wrapper:*:*:*:*:*:*:*:*
tags:
  - cve-2026-14265
  - rce
  - deserialization
vendors:
  - AWS
products:
  - AWS Advanced JDBC Wrapper
cves:
  - id: CVE-2026-14265
    cvss: 7.5
    epss: 0.00727
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-c5q4-97jw-jggh
  - https://cveawg.mitre.org/api/cve/CVE-2026-14265
---

## Overview
The AWS Advanced JDBC Wrapper is vulnerable to remote code execution (CVE-2026-14265) due to insecure Java deserialization within the RemoteQueryCachePlugin. When this plugin is enabled, it deserializes query results from a shared Redis or Valkey cache using ObjectInputStream without class filtering. 

## Attack Chain
An actor with write access to the shared cache infrastructure can inject a crafted serialized Java object. When an application server reads these cached query results via the RemoteQueryCachePlugin, the application deserializes the crafted object, resulting in arbitrary code execution.

## Impact
Successful exploitation allows an actor to execute arbitrary code on the application server. The vulnerability requires the RemoteQueryCachePlugin to be enabled and relies on the actor having write access to the shared cache infrastructure.

## Recommendation
Users should upgrade to AWS Advanced JDBC Wrapper version 4.0.1 or later. If an immediate upgrade is not possible, the RemoteQueryCachePlugin should be disabled, and write access to the Redis or Valkey cache infrastructure should be restricted to trusted principals.
