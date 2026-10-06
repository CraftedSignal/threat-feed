---
title: Denial of Service via Memory Leak in Node.js compression Middleware
slug: 2026-10-compression-dos
description: The compression middleware for Node.js is vulnerable to a memory leak leading to Denial of Service when an attacker prematurely closes connections during compressed response transmission.
date: "2026-10-06T00:45:48Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:nodejs:compression:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - nodejs
  - middleware
  - vulnerability
vendors:
  - Node.js Foundation
products:
  - compression (< 1.8.2)
cves:
  - id: CVE-2026-87776
    cvss: 7.5
    epss: 0.00608
references:
  - https://github.com/advisories/GHSA-vc2v-76pw-4v95
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-87776
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade compression package to 1.8.2 across all Node.js projects
      owner: Development
      due: 48h
      evidence: Users should upgrade to 1.8.2.
  mitigation_plan:
    - priority: immediate
      action: Upgrade compression to 1.8.2
      owner: Development
      addresses: CVE-2026-87776
      evidence: Users should upgrade to 1.8.2.
---

The npm compression package, a common middleware used in Node.js applications, contains a memory leak vulnerability identified as CVE-2026-87776. The issue exists in versions prior to 1.8.2. When an application utilizes this middleware to compress HTTP responses, the underlying zlib stream object must be properly destroyed upon completion or connection termination. Due to a flaw in how the stream lifecycle is managed, if a client prematurely aborts the connection while the compressed data is being streamed, the zlib stream is not garbage collected and remains in memory.

This behavior is problematic because the leak occurs at the native zlib layer. An attacker can repeatedly send requests to endpoints served by the compression middleware and terminate the connection before the server finishes sending the response. Each such event consumes a small amount of memory, which does not get reclaimed. Consequently, an unauthenticated attacker can perform a sustained, low-bandwidth attack to exhaust the process memory, ultimately causing the Node.js application to crash due to a heap out-of-memory condition.

## Impact

Successful exploitation of CVE-2026-87776 results in a Denial of Service for the targeted Node.js application. Because the memory is leaked in the native zlib layer and not immediately managed by the V8 garbage collector, memory exhaustion can occur relatively quickly depending on the number of concurrent connections and the frequency of the attack. All Node.js applications that deploy the compression middleware and expose compressed endpoints are potentially susceptible to service disruption if exposed to the public internet or untrusted networks.

## Recommendation

Prioritize the upgrade of the compression package to version 1.8.2 or later to include the fix for CVE-2026-87776. There are no known application-level workarounds that can safely mitigate this behavior without applying the patch. 

- Upgrade `compression` to 1.8.2 in `package.json` and redeploy all affected services immediately.
- Monitor server-side process memory utilization for unexplained upward trends that correlate with high volumes of connection resets.
