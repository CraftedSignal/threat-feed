---
title: Steeltoe.Discovery.Eureka Deserialization Denial-of-Service (CVE-2026-50196)
slug: 2026-07-steeltoe-eureka-deserialization-dos
description: The Steeltoe.Discovery.Eureka client contains a vulnerability (CVE-2026-50196) where its `DataCenterInfo.FromJson` method throws an `ArgumentException` if a `DataCenterInfo.name` value other than 'MyOwn' or 'Amazon' is encountered, specifically missing the valid 'Netflix' value from the Java Eureka specification, which causes the local service registry to become permanently empty or stale, leading to a complete service discovery outage for all connected Steeltoe Eureka clients.
date: "2026-07-03T11:23:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - service-discovery
  - .net
  - java
  - denial-of-service
vendors:
  - Steeltoe
products:
  - 'Steeltoe.Discovery.Eureka (vulnerable: >= 4.0.0, <= 4.1.0)'
  - 'Steeltoe.Discovery.Eureka (vulnerable: <= 3.3.0)'
affected_os:
  - Windows
  - Linux
cves:
  - id: CVE-2026-50196
    cvss: 7.5
    epss: 0.00339
references:
  - https://github.com/advisories/GHSA-j8ph-6fxj-g533
---

The Steeltoe.Discovery.Eureka client contains a critical vulnerability, identified as CVE-2026-50196, that can lead to a complete service discovery outage. The flaw resides in the `DataCenterInfo.FromJson` method, which is responsible for deserializing service registry information. This method incorrectly throws an `ArgumentException` when it encounters any `DataCenterInfo.name` value other than "MyOwn" or "Amazon". Crucially, the valid "Netflix" value, specified in the Java Eureka standard, is unrecognized. This exception propagates through the entire registry deserialization chain and is silently swallowed by the client's periodic cache refresh task. Consequently, the Steeltoe client's local service registry remains permanently empty or stale, severing its ability to perform service lookups. This issue affects versions `>= 4.0.0, <= 4.1.0` and versions `<= 3.3.0` of the `nuget/Steeltoe.Discovery.Eureka` package. It matters for defenders because a single, legitimate registration by a Java or Spring service in a mixed environment can inadvertently trigger a widespread denial of service for all Steeltoe clients.

## Attack Chain

1. A legitimate non-Steeltoe Eureka client (e.g., a Java or Spring Boot application) registers itself with a Eureka server.
2. The registering client sends its `DataCenterInfo.name` as "Netflix", which is a valid value according to the Java Eureka specification.
3. A Steeltoe Eureka client (using the vulnerable `Steeltoe.Discovery.Eureka` package) attempts to fetch the full service registry from the Eureka server via an HTTP GET request.
4. During the internal deserialization process of the fetched registry data, the Steeltoe client's `DataCenterInfo.FromJson` method encounters the "Netflix" value for `DataCenterInfo.name`.
5. The `DataCenterInfo.FromJson` method, which only recognizes "MyOwn" or "Amazon" as valid names, incorrectly throws an `ArgumentException`.
6. This `ArgumentException` propagates through the registry fetch process and is subsequently swallowed by the Steeltoe client's periodic cache refresh task.
7. The Steeltoe client's local service registry cache fails to populate or update, leading to a persistent empty or stale state.
8. Impact: All services relying on this Steeltoe client for service discovery experience a complete outage due to the inability to resolve service lookups, which persists until the triggering registration is removed.

## Impact

The vulnerability results in a complete and persistent service discovery outage for all Steeltoe Eureka clients connected to the affected registry. New clients will start with an empty service registry, while running clients will cease to refresh their local cache, effectively rendering them unable to locate or communicate with other services. This outage is triggered by the presence of a single registration with an unrecognized `DataCenterInfo.name` (such as "Netflix", which is valid in Java Eureka). It can be inadvertently caused by legitimate Java or Spring services in a mixed environment, leading to widespread unavailability across microservice architectures until the problematic registration is manually removed from the Eureka server.

## Recommendation

*   Prioritize upgrading all instances of `Steeltoe.Discovery.Eureka` to a patched version that addresses CVE-2026-50196.
*   If immediate upgrade is not possible, audit your Eureka registry for any registrations using `DataCenterInfo.name` values other than "MyOwn" or "Amazon", specifically "Netflix", and remove them.
*   In environments with mixed Java/Spring and Steeltoe Eureka clients, proactively audit for the presence of the `Netflix` data center type before deploying Steeltoe Eureka clients to prevent CVE-2026-50196 from being triggered.
