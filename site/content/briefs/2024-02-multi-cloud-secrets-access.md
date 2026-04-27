---
title: Multiple Cloud Secrets Accessed by Single Source IP
slug: 2024-02-multi-cloud-secrets-access
description: A single source IP accessing secret-management APIs across multiple cloud providers (AWS, GCP, Azure) and Kubernetes clusters within a short timeframe indicates potential credential theft, session hijacking, or token replay.
date: "2026-04-10T16:27:52Z"
severities:
  - high
tags:
  - credential-access
  - cloud
  - kubernetes
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
  - https://docs.cloud.google.com/secret-manager/docs/samples/secretmanager-access-secret-version
  - https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets
  - https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
rules:
  - title: Multiple Cloud Secrets Accessed by Source Address
    description: Detects a single source IP accessing secret-management APIs across multiple cloud providers (AWS, GCP, Azure) and Kubernetes clusters.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555.006
    data_sources:
      - network_connection
      - cloudtrail|azure|gcp|kubernetes
  - title: Multiple Cloud Secrets Accessed by User Agent
    description: Detects multiple cloud secrets accessed by the same user agent in different cloud environments
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.006
    data_sources:
      - webserver
      - linux|windows
rules_count: 2
---

This threat brief focuses on the detection of potential credential compromise and abuse in multi-cloud environments. The core issue is the observation of a single source IP address accessing secret stores across multiple cloud providers (AWS Secrets Manager, Google Secret Manager, Azure Key Vault) and Kubernetes clusters within a short timeframe. This behavior, detected by the Elastic rule "Multiple Cloud Secrets Accessed by Source Address" published on 2026-04-10, is indicative of an adversary…
