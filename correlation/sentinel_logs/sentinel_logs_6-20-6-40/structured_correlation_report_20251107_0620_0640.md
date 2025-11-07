# 🔒 Security Correlation Analysis Report

**Generated:** 2025-11-07T17:27:39.537177  
**Analysis Engine:** CrewAI + Gemini 2.0 Flash (Optimized)  
**Total Events Analyzed:** 12

---

## 📊 Executive Summary

Identified a high-risk session hijacking incident due to impossible travel. Also, repeated failed logons with behavioral anomalies suggest potential credential stuffing. MFA policy gaps for guest users require immediate attention. First-time application usage by a guest user and successful MFA via token claims are low-priority events.

---

## 📈 Summary Statistics

- 🔴 **High Priority Events:** 2
- 🟡 **Medium Priority Events:** 1
- 🟢 **Low Priority Events:** 2

---

## 🔴 HIGH PRIORITY EVENTS (Immediate Action Required)

### 🚨 Event 1: Impossible Travel / Session Hijacking for Sam Malviya

**Event ID:** `5ec66138-168c-43e4-8938-c90bca70cf1e`  
**Timestamp:** `Unknown`  
**Risk Score:** 10/10

#### 👤 User Information
- **User:** sam.malviya@yashtechnologies841.onmicrosoft.com
- **User ID:** `Unknown`
- **Type:** Unknown
- **Display Name:** Sam Malviya

#### 📍 Location & Network
- **Location:** Unknown, Unknown
- **IP Address:** `Unknown`
- **ISP:** Unknown

#### 🔐 Authentication Details
- **Method:** Unknown
- **Requirement:** Unknown
- **MFA Detail:** Previously satisfied
- **Result Code:** `Unknown`
- **Result:** Unknown

#### 💻 Application & Resource
- **Application:** Unknown
- **App ID:** `Unknown`
- **Resource:** Unknown

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
- Impossible travel
- Session hijacking

**Behavioral Patterns:**
- Geographic anomaly
- MFA bypass

**Attack Vector:** Session hijacking

**Recommended Actions:**
1. Revoke all active sessions
2. Force password reset
3. Endpoint investigation

**Related Events:** None identified

**Raw Event Summary:** Impossible travel detected for Sam Malviya due to geographically distant logins within a short timeframe, indicating potential session hijacking.

---

### 🚨 Event 2: Repeated Failed Logons to Azure Portal with Extensive Behavioral Anomalies by Pooja Gupta

**Event ID:** `2b32a2b3-111f-4eb5-ac67-7dba1ae3d600`  
**Timestamp:** `Unknown`  
**Risk Score:** 9/10

#### 👤 User Information
- **User:** gupta.pooja@yashtechnologies841.onmicrosoft.com
- **User ID:** `Unknown`
- **Type:** Unknown
- **Display Name:** Pooja Gupta

#### 📍 Location & Network
- **Location:** Mumbai, India
- **IP Address:** `27.107.64.154`
- **ISP:** Unknown

#### 🔐 Authentication Details
- **Method:** Password
- **Requirement:** Unknown
- **MFA Detail:** N/A
- **Result Code:** `Failure`
- **Result:** User account does not exist in tenant

#### 💻 Application & Resource
- **Application:** Azure Portal
- **App ID:** `Unknown`
- **Resource:** Azure Resource Manager

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
- Failed logon attempts
- Behavioral anomalies

**Behavioral Patterns:**
- First-time user
- Uncommon app usage

**Attack Vector:** Credential stuffing

**Recommended Actions:**
1. User verification
2. Blocking
3. Threat hunting

**Related Events:** None identified

**Raw Event Summary:** Repeated failed logons to Azure Portal by Pooja Gupta with numerous behavioral anomalies, suggesting credential stuffing or reconnaissance.

---

## 🟡 MEDIUM PRIORITY EVENTS (Investigation Recommended)

### ⚠️ Event 1: MFA Policy Gaps for Guest Users

**Event ID:** `d04ceef8-441e-45c7-b4cd-89ae4afd9935`  
**Timestamp:** `Unknown`  
**Risk Score:** 7/10

#### 👤 User Information
- **User:** Unknown
- **User ID:** `Unknown`
- **Type:** Guest
- **Display Name:** Unknown

#### 📍 Location & Network
- **Location:** Unknown, Unknown
- **IP Address:** `Unknown`
- **ISP:** Unknown

#### 🔐 Authentication Details
- **Method:** singleFactorAuthentication
- **Requirement:** Unknown
- **MFA Detail:** Previously satisfied
- **Result Code:** `Success`
- **Result:** Unknown

#### 💻 Application & Resource
- **Application:** Unknown
- **App ID:** `Unknown`
- **Resource:** Unknown

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
- MFA bypass
- Guest user activity

**Behavioral Patterns:**
- First-time app usage

**Attack Vector:** Credential compromise

**Recommended Actions:**
1. Enforce MFA
2. Guest access review
3. Monitor guest activity

**Related Events:** None identified

**Raw Event Summary:** MFA policy gaps detected for guest users, with successful authentication using single-factor authentication and MFA previously satisfied.

---

## 🟢 LOW PRIORITY EVENTS (Informational)

### ℹ️ Event 1: Prajvi Jain - First-Time Application Usage (Successful Authentication)

**Event ID:** `f2c57414-c729-476e-b155-1d2d40f805cf`  
**Timestamp:** `Unknown`  
**Risk Score:** 3/10

#### 👤 User Information
- **User:** prajvi.jain@yash.com
- **User ID:** `Unknown`
- **Type:** Guest
- **Display Name:** Prajvi Jain

#### 📍 Location & Network
- **Location:** New Delhi, Unknown
- **IP Address:** `Unknown`
- **ISP:** Unknown

#### 🔐 Authentication Details
- **Method:** Unknown
- **Requirement:** Unknown
- **MFA Detail:** Previously satisfied
- **Result Code:** `Success`
- **Result:** Unknown

#### 💻 Application & Resource
- **Application:** YASH-SPN-UES-Grafana-Dashboard
- **App ID:** `Unknown`
- **Resource:** Unknown

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
- First-time app usage

**Attack Vector:** Unknown

**Recommended Actions:**
1. Verify authorization
2. Continued monitoring

**Related Events:** None identified

**Raw Event Summary:** Prajvi Jain, a guest user, successfully signed in to YASH-SPN-UES-Grafana-Dashboard for the first time.

---

### ℹ️ Event 2: Successful MFA via Token Claims (General)

**Event ID:** `9bc481a1-e3c3-40f9-a82f-19c4fc35ff80`  
**Timestamp:** `Unknown`  
**Risk Score:** 1/10

#### 👤 User Information
- **User:** Unknown
- **User ID:** `Unknown`
- **Type:** Unknown
- **Display Name:** Unknown

#### 📍 Location & Network
- **Location:** Unknown, Unknown
- **IP Address:** `Unknown`
- **ISP:** Unknown

#### 🔐 Authentication Details
- **Method:** Unknown
- **Requirement:** Unknown
- **MFA Detail:** Previously satisfied
- **Result Code:** `Success`
- **Result:** Unknown

#### 💻 Application & Resource
- **Application:** Unknown
- **App ID:** `Unknown`
- **Resource:** Unknown

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


**Attack Vector:** Unknown

**Recommended Actions:**
1. Session lifetime policies
2. Token protection

**Related Events:** None identified

**Raw Event Summary:** Several users successfully authenticated with MFA satisfied by existing token claims, a standard behavior for persistent sessions.

---


---

## 📝 Notes

This report was generated using AI-powered security correlation analysis. All events have been 
analyzed for behavioral anomalies, authentication patterns, and threat indicators. Please review 
high-priority events immediately and validate medium-priority events with the respective users.

**Report Generated By:** Advanced Security Correlation Engine v2.0 (Optimized)
