---
title: Immutable.js Map/Set Hash Collision Denial of Service Vulnerability
slug: 2026-07-immutable-map-hash-collision-dos
description: A high-severity algorithmic complexity vulnerability (CVE-2026-59880) in the Immutable.js library's `Immutable.Map` and `Immutable.Set` allows an attacker to craft object keys that cause hash collisions, degrading performance from O(1) to O(N²) and leading to a CPU-bound denial of service in applications, particularly those running on single-threaded Node.js environments that ingest untrusted input as object keys.
date: "2026-07-21T19:05:11Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:immutable-js:immutable:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - algorithmic-complexity
  - immutable-js
  - nodejs
  - vulnerability
vendors:
  - Immutable.js
products:
  - Immutable.js (< 4.3.9)
  - Immutable.js (>= 5.0.0-beta.1, < 5.1.8)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
    evidence: The string hash is public and deterministic, so an attacker who controls the keys inserted into a Map can craft many keys that all collide
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1499
    technique_name: Denial of Service
    evidence: A small, attacker-shaped payload can therefore consume disproportionate CPU and, on a single-threaded runtime such as Node.js, stall the event loop and deny service.
    confidence_band: high
cves:
  - id: CVE-2026-59880
    cvss: 7.5
    epss: 0.0037
references:
  - https://github.com/advisories/GHSA-xvcm-6775-5m9r
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-59880
---

A high-severity algorithmic complexity vulnerability, identified as CVE-2026-59880, affects all versions of the Immutable.js library through 5.1.7, specifically within its `Immutable.Map` and `Immutable.Set` data structures. Threat actors can exploit this by crafting malicious input where object keys are designed to produce identical 32-bit hash values according to Immutable.js's deterministic string hashing algorithm. When these keys are inserted into or looked up within `Immutable.Map` or `Immutable.Set`, the collision resolution mechanism - a linear scan of a collision bucket - causes operations to degrade from an amortized O(1) to O(N) for single operations and O(N²) for building or reading the entire set. This disproportionately consumes CPU resources, leading to a CPU-bound denial of service, particularly impactful for single-threaded JavaScript runtimes like Node.js, which can cause the application's event loop to stall and render the service unavailable. The vulnerability primarily affects applications that ingest untrusted user input (e.g., from request bodies) and use it directly as object keys within Immutable.js structures.

## Attack Chain

1. **Reconnaissance**: An attacker identifies a target application utilizing the Immutable.js library and determines that it processes untrusted user input, such as HTTP request bodies, directly into `Immutable.Map` or `Immutable.Set` structures.
2. **Algorithm Analysis**: The attacker analyzes the Immutable.js deterministic string hashing algorithm (JVM-style polynomial `hashed = (31 * hashed + charCode) | 0`) to understand how hash collisions can be engineered.
3. **Payload Crafting**: Using the deterministic hashing algorithm, the attacker generates a large set of distinct string keys that all produce the same 32-bit hash value. For example, strings like "Aa" and "BB" hash to the same value (2112), allowing for exponential growth in colliding keys with minimal length.
4. **Initial Access / Delivery**: The attacker sends a crafted payload, typically as a JSON object within an HTTP POST request body, to the vulnerable application endpoint. The crafted strings are used as keys in this JSON object.
5. **Processing**: The application receives the request and attempts to parse the untrusted input, initializing an `Immutable.Map` or `Immutable.Set` (e.g., via `Immutable.Map(req.body)` or `Immutable.fromJS(req.body)`) using the attacker-controlled keys.
6. **Resource Consumption**: As the application inserts or accesses these colliding keys, the Immutable.js data structures are forced to perform linear scans within their collision buckets. This degrades performance to O(N²) time complexity for processing the entire set of keys.
7. **Denial of Service**: The excessive CPU consumption caused by the inefficient algorithmic operations leads to a CPU-bound denial of service. In single-threaded runtimes like Node.js, this stalls the event loop, preventing the application from processing legitimate requests and rendering it unresponsive.

## Impact

Successful exploitation of CVE-2026-59880 results in a severe CPU-bound denial of service for affected applications. This can lead to complete service unavailability, preventing legitimate users from accessing the application's functionalities. The impact is particularly critical for applications built on single-threaded runtimes such as Node.js, where a single malicious request can stall the entire event loop, bringing the application to a halt. While no specific victim counts or industry targets are provided, any application using `Immutable.js` versions prior to `5.1.8` and ingesting untrusted input directly into `Immutable.Map` or `Immutable.Set` is susceptible. The vulnerability causes the server to consume disproportionate CPU resources, wasting computational cycles and potentially incurring higher infrastructure costs due to auto-scaling or prolonged unavailability.

## Recommendation

* **Patch Vulnerable Libraries**: Immediately upgrade the `Immutable.js` library to version `5.1.8` or newer to remediate CVE-2026-59880. This version introduces a per-process seeded secondary hash to handle large collision buckets efficiently.
* **Implement Input Validation**: For applications that cannot be immediately patched, implement strict input validation to cap request body size and limit the number and length of object keys processed from untrusted sources, thereby preventing attacker-controlled payloads from reaching `Immutable.Map` or `Immutable.Set`.
* **Avoid Direct Key Ingestion**: Review application code to identify instances where untrusted data, especially object keys from sources like `req.body`, are directly used to construct `Immutable.Map` or `Immutable.Set` and implement sanitization or alternative processing.
