---
title: Oracle Java SE, GraalVM Networking Component Denial-of-Service Vulnerability (CVE-2026-34282)
slug: 2026-04-java-dos
description: CVE-2026-34282 is a remotely exploitable vulnerability in the Networking component of Oracle Java SE and GraalVM that allows an unauthenticated attacker to cause a complete denial of service.
date: "2026-04-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - CVE-2026-34282
  - java
  - graalvm
  - dos
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
cves:
  - id: CVE-2026-34282
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34282
rules:
  - title: Detect Suspicious Java Network Activity
    description: Detects unusual network activity by Java processes that may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Java Process Crashing
    description: Detects Java processes that crash, potentially indicating a denial-of-service condition related to CVE-2026-34282.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-34282 is a critical vulnerability affecting the Networking component of Oracle Java SE, Oracle GraalVM for JDK, and Oracle GraalVM Enterprise Edition. The vulnerability, present in versions 8u481-perf, 11.0.30, 17.0.18, 21.0.10, 25.0.2, and 26 of Oracle Java SE, GraalVM for JDK versions 17.0.18 and 21.0.10, and GraalVM Enterprise Edition 21.3.17, allows an unauthenticated attacker with network access to trigger a complete denial-of-service (DoS) condition. This is achieved by sending specially crafted network requests to APIs within the affected Networking component, potentially through web services. Successful exploitation results in a hang or repeatable crash of the Java SE or GraalVM instance. The vulnerability is particularly concerning for Java deployments running sandboxed Java Web Start applications or applets that load and execute untrusted code from sources like the internet.

## Attack Chain

1.  The attacker identifies a vulnerable Oracle Java SE or GraalVM instance accessible over the network. This could be a web server running a Java-based web application, or a client running a Java applet.
2.  The attacker crafts a malicious network request specifically designed to exploit the Networking component vulnerability (CVE-2026-34282). The specific protocol is not defined, but the vulnerability description suggests multiple protocols could be leveraged.
3.  The attacker sends the malicious request to a network port exposed by the vulnerable Java application or service. This could be port 80 (HTTP), 443 (HTTPS), or a custom port used by the application.
4.  The vulnerable Networking component processes the malicious request. Due to the flaw in the code, the request triggers an unhandled exception or resource exhaustion within the Java Virtual Machine (JVM).
5.  The JVM enters a hung state, becomes unresponsive, or crashes entirely. This could also lead to a repeatable crash loop.
6.  Legitimate users of the application or service are unable to access it.
7.  If the vulnerable application is critical to business operations, this can lead to significant disruption and financial loss.

## Impact

Successful exploitation of CVE-2026-34282 leads to a complete denial-of-service condition. Affected Java SE and GraalVM instances become unresponsive or crash repeatedly, disrupting services and applications that rely on them. This vulnerability could impact various sectors, including finance, healthcare, and e-commerce, wherever Java-based applications are deployed. The potential number of victims is substantial, considering the widespread use of Java and GraalVM in enterprise environments. If exploited, it can cause significant downtime, data loss, and reputational damage.

## Recommendation

*   Immediately apply the patches provided by Oracle for CVE-2026-34282 to all affected Oracle Java SE and GraalVM installations.
*   Monitor web server logs for suspicious network requests targeting Java-based applications to detect potential exploitation attempts. Deploy the Sigma rule `Detect Suspicious Java Network Activity` to identify anomalous network behavior related to Java processes.
*   Review and harden the network perimeter to restrict access to vulnerable Java-based applications or services, minimizing the attack surface.
*   Implement intrusion detection systems (IDS) or intrusion prevention systems (IPS) to detect and block malicious network traffic attempting to exploit CVE-2026-34282.
*   For environments running sandboxed Java Web Start applications or applets, ensure that the Java sandbox is properly configured and up-to-date to mitigate the risk of running untrusted code.
