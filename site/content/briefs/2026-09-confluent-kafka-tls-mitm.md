---
title: Improper TLS Certificate Validation in confluent-kafka
slug: 2026-09-confluent-kafka-tls-mitm
description: The confluent-kafka library contains a vulnerability in the HcVaultKmsClient component where TLS certificate verification is explicitly disabled, allowing attackers with a network MITM position to steal Vault tokens or AppRole credentials.
date: "2026-09-26T10:39:19Z"
type: advisory
types:
  - advisory
severities:
  - high
---

The confluent-kafka library, specifically the HcVaultKmsClient component, suffers from a critical security flaw (CVE-2026-57836) resulting from improper TLS certificate validation. The library hardcodes 'verify=False' when initializing the HashiCorp Vault client, which disables SSL/TLS certificate verification by default. This design choice persists across confluent-kafka versions 2.8.0 through 2.14.2. An attacker capable of establishing a Man-in-the-Middle (MITM) position between the application using confluent-kafka and its configured HashiCorp Vault instance can intercept, read, and manipulate sensitive authentication traffic. This allows for the exfiltration of Vault tokens and AppRole credentials, potentially enabling the attacker to impersonate the Vault server or gain unauthorized access to secrets managed by the Vault instance. This vulnerability is mitigated in version 2.15.0, which enables TLS verification by default and introduces configurable CA and certificate support.

## Attack Chain

1. The target application is configured to use HcVaultKmsClient for secret management via confluent-kafka versions 2.8.0-2.14.2.
2. The attacker establishes a network MITM position, such as through ARP spoofing, DNS poisoning, or compromised routing infrastructure.
3. The target application initiates a connection to the configured HashiCorp Vault server.
4. The HcVaultKmsClient component attempts to connect to the Vault API, ignoring TLS certificate validation errors due to the hardcoded 'verify=False' configuration.
5. The attacker intercepts the HTTPS traffic, presenting a self-signed or otherwise untrusted certificate to the application.
6. The application accepts the malicious certificate without warning and proceeds to send authentication requests (token or AppRole login).
7. The attacker logs the authentication credentials (Vault token or RoleID/SecretID) sent in the request headers or body.
8. The attacker uses the stolen credentials to access secrets or resources within the HashiCorp Vault environment.

## Impact

Successful exploitation allows for the complete compromise of Vault credentials used by applications employing the confluent-kafka library. This can lead to unauthorized data access, lateral movement within the environment, and full compromise of the secrets stored within the targeted HashiCorp Vault instance.
