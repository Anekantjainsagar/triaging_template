# 🔒 Security Correlation Analysis Report

**Generated:** 2025-11-07T19:35:50.451234  
**Analysis Engine:** CrewAI + Gemini 2.0 Flash (Optimized + Data Enriched)  
**Total Events Analyzed:** 10

---

## 📊 Executive Summary

Impossible travel events and inconsistent MFA enforcement indicate potential account compromises. Immediate action is required to mitigate these high-risk findings. Conditional Access policies are in reportOnly mode, creating vulnerabilities.

---

## 📈 Summary Statistics

- 🔴 **High Priority Events:** 3
- 🟡 **Medium Priority Events:** 2
- 🟢 **Low Priority Events:** 1

---

## 🔴 HIGH PRIORITY EVENTS (Immediate Action Required)

### 🚨 Event 1: Impossible travel detected for Prabhat Sutar

**Event ID:** `80b0c5f9-1550-4976-8695-68969013c644`  
**Timestamp:** `2025-11-07T06:15:01.6835517Z`  
**Risk Score:** 10/10

#### 👤 User Information
- **User:** ajinkya.bhagwat@yash.com
- **User ID:** `3d2143b0-fbe9-44b0-8895-11d69db48801`
- **Type:** Guest
- **Display Name:** Salunke Ajinkya  Bhagwat

#### 📍 Location & Network
- **Location:** Chhindwara, IN
- **IP Address:** `2409:4043:684:808f:ee06:b9c3:51b7:1526`
- **ISP:** N/A

#### 🔐 Authentication Details
- **Method:** Unknown
- **Requirement:** singleFactorAuthentication
- **MFA Detail:** N/A
- **Result Code:** `0`
- **Result:** Success

#### 💻 Application & Resource
- **Application:** YASH-SPN-UES-Azure-App
- **App ID:** `b8d957b6-3709-49a0-b182-1bc63498c116`
- **Resource:** Microsoft Graph

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ❌
- Uncommonly Used Browser: ❌
- Investigation Priority: 10

#### 🔍 Correlation Analysis

**Threat Indicators:**
- Impossible Travel

**Behavioral Patterns:**
- Rapid Location Change

**Attack Vector:** Compromised Credentials

**Recommended Actions:**
1. Force Password Reset
2. Revoke Sessions

**Related Events:** None identified

**Raw Event Summary:** Impossible travel detected between Bhopal and New Delhi.

---

### 🚨 Event 2: Impossible travel detected for Prakhar Vyas

**Event ID:** `e951899c-8d52-49ed-b5ea-e5947452a791`  
**Timestamp:** `2025-11-07T06:15:23.5459477Z`  
**Risk Score:** 10/10

#### 👤 User Information
- **User:** prakhar.vyas@yashtechnologies841.onmicrosoft.com
- **User ID:** `83700f8f-ee89-4c7e-baef-57e3d336d98e`
- **Type:** Member
- **Display Name:** Prakhar Vyas

#### 📍 Location & Network
- **Location:** Mumbai, IN
- **IP Address:** `14.194.129.210`
- **ISP:** N/A

#### 🔐 Authentication Details
- **Method:** Previously satisfied
- **Requirement:** singleFactorAuthentication
- **MFA Detail:** N/A
- **Result Code:** `0`
- **Result:** Success

#### 💻 Application & Resource
- **Application:** PowerApps - apps.powerapps.com
- **App ID:** `3e62f81e-590b-425b-9531-cad6683656cf`
- **Resource:** PowerApps Service

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ❌
- Uncommonly Used Browser: ❌
- Investigation Priority: 10

#### 🔍 Correlation Analysis

**Threat Indicators:**
- Impossible Travel

**Behavioral Patterns:**
- Rapid Location Change

**Attack Vector:** Compromised Credentials

**Recommended Actions:**
1. Force Password Reset
2. Revoke Sessions

**Related Events:** None identified

**Raw Event Summary:** Impossible travel detected between Mumbai and New Delhi.

---

### 🚨 Event 3: Multiple first-time anomalies with unenforced MFA

**Event ID:** `2a697af5-88e6-4c53-b2dd-b96d4e2af4d1`  
**Timestamp:** `2025-11-07T06:15:32.8901487Z`  
**Risk Score:** 9/10

#### 👤 User Information
- **User:** ajinkya.bhagwat@yash.com
- **User ID:** `3d2143b0-fbe9-44b0-8895-11d69db48801`
- **Type:** Guest
- **Display Name:** Salunke Ajinkya  Bhagwat

#### 📍 Location & Network
- **Location:** Chhindwara, IN
- **IP Address:** `2409:4043:684:808f:ee06:b9c3:51b7:1526`
- **ISP:** N/A

#### 🔐 Authentication Details
- **Method:** Previously satisfied
- **Requirement:** singleFactorAuthentication
- **MFA Detail:** N/A
- **Result Code:** `0`
- **Result:** Success

#### 💻 Application & Resource
- **Application:** YASH-SPN-UES-Azure-App
- **App ID:** `b8d957b6-3709-49a0-b182-1bc63498c116`
- **Resource:** Microsoft Graph

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ❌
- Uncommonly Used Browser: ❌
- Investigation Priority: 1

#### 🔍 Correlation Analysis

**Threat Indicators:**
- First Time Browser
- Uncommon Browser

**Behavioral Patterns:**
- New User Behavior

**Attack Vector:** Compromised Credentials

**Recommended Actions:**
1. Verify User Activity
2. Force Password Reset

**Related Events:** None identified

**Raw Event Summary:** First time browser and uncommon browser used with no MFA.

---

## 🟡 MEDIUM PRIORITY EVENTS (Investigation Recommended)

### ⚠️ Event 1: First-time application usage with unenforced MFA

**Event ID:** `8f913f63-8de2-4d49-8ca1-93f74144db11`  
**Timestamp:** `2025-11-07T06:15:59.4271629Z`  
**Risk Score:** 6/10

#### 👤 User Information
- **User:** prabhat.sutar@yash.com
- **User ID:** `5364c24a-51fb-4641-a30f-5179dc3c3ca5`
- **Type:** Guest
- **Display Name:** Prabhat Sutar

#### 📍 Location & Network
- **Location:** Bhopal, IN
- **IP Address:** `2409:40c4:f:8aec:a1ad:938d:cb33:5f5f`
- **ISP:** N/A

#### 🔐 Authentication Details
- **Method:** Previously satisfied
- **Requirement:** multiFactorAuthentication
- **MFA Detail:** N/A
- **Result Code:** `0`
- **Result:** Success

#### 💻 Application & Resource
- **Application:** YASH-SPN-UES-Azure-App
- **App ID:** `b8d957b6-3709-49a0-b182-1bc63498c116`
- **Resource:** Microsoft Graph

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ❌
- Uncommonly Used Browser: ❌
- Investigation Priority: 2

#### 🔍 Correlation Analysis

**Threat Indicators:**
- First Time App Use

**Behavioral Patterns:**
- New App Access

**Attack Vector:** Unauthorized Access

**Recommended Actions:**
1. Verify User Activity

**Related Events:** None identified

**Raw Event Summary:** First time app usage with no MFA enforced.

---

### ⚠️ Event 2: Azure Portal Access by Guest User

**Event ID:** `67c88c43-ce7d-4eca-82f6-6dce7f7dac5c`  
**Timestamp:** `2025-11-07T06:19:04.1249337Z`  
**Risk Score:** 5/10

#### 👤 User Information
- **User:** prabhat.sutar@yash.com
- **User ID:** `5364c24a-51fb-4641-a30f-5179dc3c3ca5`
- **Type:** Guest
- **Display Name:** Prabhat Sutar

#### 📍 Location & Network
- **Location:** New Delhi, IN
- **IP Address:** `125.23.93.22`
- **ISP:** N/A

#### 🔐 Authentication Details
- **Method:** Previously satisfied
- **Requirement:** multiFactorAuthentication
- **MFA Detail:** N/A
- **Result Code:** `0`
- **Result:** Success

#### 💻 Application & Resource
- **Application:** YASH-SPN-UES-Azure-App
- **App ID:** `b8d957b6-3709-49a0-b182-1bc63498c116`
- **Resource:** Microsoft Graph

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ❌
- Uncommonly Used Browser: ❌
- Investigation Priority: 3

#### 🔍 Correlation Analysis

**Threat Indicators:**
- Guest User Access

**Behavioral Patterns:**
- Privileged Access

**Attack Vector:** Insider Threat

**Recommended Actions:**
1. Review Permissions

**Related Events:** None identified

**Raw Event Summary:** Guest user accessing Azure Portal with MFA.

---

## 🟢 LOW PRIORITY EVENTS (Informational)

### ℹ️ Event 1: "Keep me signed in" Interrupt

**Event ID:** `5ec66138-168c-43e4-8938-c90bca70cf1e`  
**Timestamp:** `2025-11-07T06:24:10.257969Z`  
**Risk Score:** 1/10

#### 👤 User Information
- **User:** prajvi.jain@yash.com
- **User ID:** `433462c1-12e5-40b4-b194-b3bb621b5c63`
- **Type:** Guest
- **Display Name:** Prajvi Jain

#### 📍 Location & Network
- **Location:** New Delhi, IN
- **IP Address:** `125.23.93.22`
- **ISP:** N/A

#### 🔐 Authentication Details
- **Method:** Previously satisfied
- **Requirement:** singleFactorAuthentication
- **MFA Detail:** N/A
- **Result Code:** `0`
- **Result:** Success

#### 💻 Application & Resource
- **Application:** YASH-SPN-UES-Azure-App
- **App ID:** `b8d957b6-3709-49a0-b182-1bc63498c116`
- **Resource:** Microsoft Graph

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ❌
- Uncommonly Used Browser: ❌
- Investigation Priority: N/A

#### 🔍 Correlation Analysis

**Threat Indicators:**


**Behavioral Patterns:**


**Attack Vector:** None

**Recommended Actions:**


**Related Events:** None identified

**Raw Event Summary:** "Keep me signed in" interrupt during sign-in.

---


---

## 📝 Notes

This report was generated using AI-powered security correlation analysis. All events have been 
analyzed for behavioral anomalies, authentication patterns, and threat indicators. Please review 
high-priority events immediately and validate medium-priority events with the respective users.

**Report Generated By:** Advanced Security Correlation Engine v2.0 (Optimized)
