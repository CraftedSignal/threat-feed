---
title: Hyperledger Fabric SDK Java Deserialization RCE
slug: 2024-01-26-fabric-deserialization
description: The deprecated fabric-sdk-java client SDK is vulnerable to Java deserialization RCE due to the use of ObjectInputStream.readObject() without an ObjectInputFilter in Channel.java, allowing remote code execution if an attacker can supply crafted serialized Channel bytes to the client application.
date: "2026-04-29T20:41:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - deserialization
  - rce
  - java
vendors:
  - Hyperledger
products:
  - fabric-sdk-java
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://github.com/advisories/GHSA-prf8-cf2x-rhx7
  - https://hyperledger.github.io/fabric-gateway/
rules:
  - title: Detect Ysoserial Payload in Network Traffic
    description: Detects network traffic characteristic of ysoserial payloads
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - network_connection
      - windows
  - title: Detect Process Calling Deserialize Method
    description: Detects a process calling the deSerializeChannel method.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `fabric-sdk-java` client SDK, a deprecated component of Hyperledger Fabric, contains a critical vulnerability related to insecure deserialization. Specifically, the `Channel.java` file implements `readObject()` and exposes `deSerializeChannel()` methods that call `ObjectInputStream.readObject()` on untrusted byte arrays without configuring an `ObjectInputFilter`. This omission allows an attacker to inject malicious serialized Java objects, leading to remote code execution (RCE). While `fabric-sdk-java` has been deprecated since Hyperledger Fabric v2.5 and replaced by `org.hyperledger.fabric:fabric-gateway`, organizations that have not yet migrated are still vulnerable. This issue highlights the risks associated with using deprecated software and the importance of migrating to supported versions. The vulnerability exists in versions 1.0.0 through 2.2.26.

## Attack Chain

1.  Attacker crafts a malicious serialized Java object using a tool like `ysoserial`. For example, `java -jar ysoserial.jar CommonsCollections6 "touch /tmp/pwned" > malicious_channel.ser`.
2.  The attacker gains the ability to supply crafted serialized Channel bytes to the client application. This could involve compromising a local channel file.
3.  The attacker injects the malicious serialized data through an application that accepts Channel bytes from external sources.
4.  The vulnerable `deSerializeChannel()` method in `Channel.java` is called with the attacker-controlled byte array.
5.  Inside `deSerializeChannel()`, an `ObjectInputStream` is created from the byte array.
6.  The `readObject()` method of `ObjectInputStream` is called without any `ObjectInputFilter`, deserializing the malicious object.
7.  The deserialization process triggers the execution of a gadget chain embedded in the malicious object.
8.  The gadget chain executes arbitrary code on the server, achieving RCE.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the server running the vulnerable `fabric-sdk-java` application. This can lead to complete system compromise, data breaches, and other malicious activities. The severity is critical due to the potential for unauthenticated remote code execution. Organizations still using the deprecated `fabric-sdk-java` are at high risk until they migrate to the supported `fabric-gateway`.

## Recommendation

*   **Migrate to `org.hyperledger.fabric:fabric-gateway` immediately** as the primary remediation, as it does not use Java serialization.
*   For organizations unable to migrate immediately, apply the suggested fix of adding an `ObjectInputFilter` to whitelist only expected classes as described in the advisory.
*   Implement runtime monitoring of Java deserialization to detect and prevent exploitation attempts.
*   Enable logging of deserialization events to aid in incident response.
