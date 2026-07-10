---
title: Azure Monitor Alert Abuse for Callback Phishing
slug: 2024-01-azure-monitor-phish
description: Adversaries are abusing Azure Monitor alert rules to deliver callback phishing emails from Microsoft's legitimate azure-noreply@microsoft.com address, embedding fraudulent billing or security lures in the alert rule description.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - azure-monitor
  - callback-phishing
  - email
vendors:
  - Microsoft
products:
  - Azure Monitor
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.bleepingcomputer.com/news/security/microsoft-azure-monitor-alerts-abused-in-callback-phishing-campaigns/
iocs:
  - type: email
    value: azure-noreply@microsoft.com
ioc_counts:
  email: 1
rules:
  - title: M365 Azure Monitor Alert Email with Financial or Billing Theme
    description: Detects Azure Monitor alert notification emails with financial or billing themed subject lines delivered to organization users from azure-noreply@microsoft.com.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566.003
    data_sources:
      - email
      - o365
  - title: M365 Azure Monitor Alert Email - Action Group Notification
    description: Detects emails indicating a user has been added to an Azure Monitor action group, which may precede a phishing email.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1566.003
    data_sources:
      - email
      - o365
rules_count: 2
---

Callback phishing campaigns are leveraging Microsoft Azure Monitor to bypass traditional email security measures. Since at least March 2026, attackers have been creating malicious alert rules within their own Azure tenants, embedding phishing lures within the description field of the alert. They then add victim email addresses to action groups associated with these alerts. When the alert is triggered, Azure Monitor sends notification emails directly to the victims from azure-noreply@microsoft.com. Because these emails originate from a legitimate Microsoft address, they pass SPF, DKIM, and DMARC checks, evading typical email security filters. The phishing lure typically involves financial or billing themes, such as fake invoices, payment references, or order confirmations, designed to induce victims to call a provided phone number.

## Attack Chain

1. The attacker creates an Azure account and sets up an Azure Monitor alert rule.
2. The attacker crafts a phishing lure, embedding it within the description field of the alert rule. The lure often involves financial themes to induce a callback.
3. The attacker adds target email addresses to an action group associated with the alert rule.
4. The attacker triggers the Azure Monitor alert rule, causing a notification email to be sent.
5. Microsoft sends an email from azure-noreply@microsoft.com to the victim, containing the phishing lure in the body of the email.
6. The victim receives the email, perceives it as legitimate due to the sender address, and is prompted to call a provided phone number.
7. The victim calls the phone number, connecting them to the attacker or an associate.
8. The attacker attempts to extract sensitive information, facilitate fraudulent payments, or install remote access tools.

## Impact

Successful callback phishing attacks can lead to credential theft, financial fraud, and unauthorized remote access to victim systems. The abuse of Azure Monitor alerts increases the likelihood of success because emails originate from a trusted Microsoft address, bypassing common email security filters. The exact number of victims is unknown, but organizations across various sectors are potentially vulnerable. If the attack succeeds, victims may suffer financial losses, data breaches, and reputational damage.

## Recommendation

*   Deploy the Sigma rule "M365 Azure Monitor Alert Email with Financial or Billing Theme" to your SIEM and tune for your environment to detect suspicious emails (rule title).
*   Implement a mail flow rule to flag or quarantine Azure Monitor notification emails that contain phone numbers or financial language in the body (description).
*   Block the sender pattern azure-noreply@microsoft.com in your email security gateway if confirmed as phishing (iocs).
*   Report suspected abusive Azure subscription IDs (found in email headers) to Microsoft abuse team for takedown (references).
