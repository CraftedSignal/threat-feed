---
title: gRPC-Go Denial of Service via HTTP/2 Fragmentation
slug: 2026-09-grpc-go-dos
description: An unauthenticated remote attacker can exploit HTTP/2 DATA frame fragmentation in gRPC-Go versions <= 1.83.0 to cause heap memory exhaustion and application crashes.
date: "2026-09-02T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:google:grpc-go:*:*:*:*:*:*:*:*
vendors:
  - Google
products:
  - gRPC-Go (<= 1.83.0)
cves:
  - id: CVE-2026-84304
references:
  - https://github.com/advisories/GHSA-vp52-pcj8-j9qc
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-84304
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all instances of google.golang.org/grpc to 1.83.1
      owner: IT Operations
      due: 48h
      evidence: The change to fix this issue is merged in master and a patch release, 1.83.1, has been published.
  mitigation_plan:
    - priority: immediate
      action: Ensure receive buffer compaction is enabled (default behavior)
      owner: IT Operations
      addresses: CVE-2026-84304
      evidence: This behavior is enabled by default.
---

The gRPC-Go library is susceptible to a remote Denial of Service (DoS) attack due to improper handling of HTTP/2 DATA frame fragmentation. By purposefully sending millions of tiny (e.g., 1-byte) HTTP/2 DATA frames within a gRPC stream, an attacker can bypass flow-control windows while inflating heap memory consumption. Each small frame incurs significant memory overhead caused by internal tracking structures and queue allocations within the gRPC-Go runtime. 

An attacker can exploit this vulnerability by multiplexing multiple concurrent streams to rapidly exhaust the memory limits of the server. This memory exhaustion results in a runtime panic or an OutOfMemory (OOM) condition, rendering the service unresponsive. This vulnerability (CVE-2026-84304) affects all versions of google.golang.org/grpc up to and including 1.83.0. Defenders must prioritize upgrading to version 1.83.1, which introduces automatic receive buffer compaction to coalesce fragmented data frames and mitigate the overhead.

## Impact

Successful exploitation leads to an unauthenticated remote Denial of Service, causing application instability or complete service failure via OOM conditions. This impacts any infrastructure, microservice architecture, or external-facing API relying on vulnerable gRPC-Go implementations.

## Recommendation

- Upgrade google.golang.org/grpc to version 1.83.1 or later to implement automatic receive buffer compaction.
- Audit existing infrastructure to identify and patch dependencies using gRPC-Go versions <= 1.83.0.
- Do not set the environment variable `GRPC_GO_EXPERIMENTAL_ENABLE_RECEIVE_BUFFER_COMPACTION=false`, as this disables the primary mitigation for this vulnerability.
