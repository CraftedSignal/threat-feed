---
title: Azure Storage Account Data Exfiltration via AzCopy and SAS Token Abuse
slug: 2024-01-02-azure-storage-azcopy-exfiltration
description: Successful GetBlob operations on Azure Storage Accounts using the AzCopy user agent with SAS token authentication can indicate data exfiltration by adversaries abusing compromised SAS tokens.
date: "2024-01-02T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - exfiltration
  - cloud-storage
  - azcopy
vendors:
  - Microsoft
products:
  - Azure Storage
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
references:
  - https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
  - https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10
  - https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview
rules:
  - title: Azure Storage Blob Exfiltration via AzCopy with SAS Token
    description: Detects GetBlob operations on Azure Storage Accounts using AzCopy user agent with SAS token authentication.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - webserver
      - azure
  - title: Azure Storage Account List and Get with AzCopy
    description: Detects list operations followed by blob retrieval by AzCopy, which is an indicator of potential enumeration followed by data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - webserver
      - azure
rules_count: 2
---

This threat involves the potential exfiltration of data from Azure Storage Accounts by abusing the AzCopy command-line utility with compromised Shared Access Signature (SAS) tokens. AzCopy is a legitimate tool for transferring data to and from Azure Storage, but adversaries can exploit it to download sensitive data if they gain access to valid SAS tokens. The activity is characterized by successful GetBlob operations originating from the AzCopy user agent and authenticated using SAS tokens. This activity is a concern for defenders because it allows attackers to bypass traditional access controls and exfiltrate data without directly compromising storage account credentials. The Elastic detection rule identifies the first occurrence of GetBlob operations from a specific storage account using this pattern.

## Attack Chain

1.  The attacker gains unauthorized access to a valid SAS token for an Azure Storage Account. This could be achieved through phishing, credential stuffing, or exploiting a misconfigured application.
2.  The attacker uses the AzCopy command-line utility on a compromised host or cloud instance.
3.  AzCopy is configured with the compromised SAS token to authenticate against the target Azure Storage Account. The attacker sets the target using the storage account name.
4.  The attacker issues a `GetBlob` request to retrieve specific blobs. They identify the target using the `objectKey`.
5.  The Azure Storage Account logs the successful `GetBlob` operation. The logs include the `AzCopy` user agent, the SAS token authentication method, and a status code of 200.
6.  The attacker repeats steps 4 and 5 to exfiltrate multiple blobs. They may first use `ListBlobs` or `ListContainers` to enumerate storage contents.
7.  The exfiltrated data is stored on the attacker's controlled infrastructure.
8.  The attacker uses the exfiltrated data for malicious purposes, such as extortion, espionage, or financial gain.

## Impact

A successful attack can lead to the exfiltration of sensitive data stored within the Azure Storage Account. The damage depends on the sensitivity of the data, which could include confidential business documents, customer data, or proprietary code. The number of victims depends on the scope of the affected storage account. Organizations in any sector that rely on Azure Storage Accounts are at risk. Data breaches can result in financial losses, reputational damage, and legal repercussions.

## Recommendation

*   Enable Azure Storage Diagnostic Logs, specifically the `StorageRead` log, and stream them to an Event Hub for analysis (references: setup section of the content).
*   Deploy the provided Sigma rule to your SIEM to detect suspicious `GetBlob` operations with the `AzCopy` user agent and SAS token authentication. Tune the rule to your environment to minimize false positives (reference: rules section below).
*   Review Azure Activity Logs for SAS token generation events to identify potentially compromised tokens (reference: overview section of the content).
*   Implement shorter expiration times and restrictive permissions on SAS tokens to limit the potential impact of compromised credentials (reference: overview section of the content).
*   Investigate alerts generated by the Sigma rule by reviewing the `azure.platformlogs.properties.accountName`, `azure.platformlogs.properties.objectKey`, `source.address`, and `azure.platformlogs.identity.tokenHash` fields to understand the context of the activity (reference: overview section of the content).
