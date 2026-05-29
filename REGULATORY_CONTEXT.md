# Regulatory Context for Incident Response

This document provides a lightweight reference mapping incident types to regulatory notification obligations. It is **not legal advice** — organizations must consult their legal counsel to determine specific obligations based on jurisdiction, data types, and contractual requirements.

---

## Purpose

During an active incident, responders need to quickly understand whether regulatory notification timelines are triggered. This document helps answer: "Do we need to notify someone, and how fast?"

---

## Notification Obligation Matrix

| Regulation | Jurisdiction | Trigger Condition | Notification Timeline | Who to Notify |
|---|---|---|---|---|
| **GDPR Art. 33** | EU/EEA | Personal data breach (access, destruction, loss, alteration, unauthorized disclosure) | 72 hours to supervisory authority | Data Protection Authority (DPA) of lead establishment |
| **GDPR Art. 34** | EU/EEA | High risk to rights and freedoms of individuals | Without undue delay to affected individuals | Data subjects directly |
| **CCPA/CPRA** | California, US | Unauthorized access to unencrypted personal information | "Most expedient time possible" (no fixed hours) | California AG + affected individuals |
| **HIPAA Breach Notification** | US (healthcare) | Unsecured protected health information (PHI) accessed | 60 days to HHS; without unreasonable delay to individuals | HHS, affected individuals, media (if >500 individuals) |
| **PCI-DSS 12.10** | Global (card data) | Compromise of cardholder data environment | Immediately to payment brands; varies by brand | Acquiring bank, payment card brands (Visa, Mastercard, etc.) |
| **PIPEDA** | Canada | Breach of security safeguards involving personal information, real risk of significant harm | "As soon as feasible" to OPC; as soon as feasible to individuals | Office of the Privacy Commissioner (OPC) + affected individuals |
| **Australian Privacy Act (NDB)** | Australia | Eligible data breach (unauthorized access/disclosure of personal information, likely serious harm) | "As soon as practicable" after assessment (30-day assessment window) | Office of the Australian Information Commissioner (OAIC) + affected individuals |
| **UK GDPR / DPA 2018** | United Kingdom | Personal data breach | 72 hours to ICO | Information Commissioner's Office (ICO) |
| **DORA (EU)** | EU (financial) | Major ICT-related incident | Initial notification within 4 hours of classification; intermediate within 72 hours; final within 1 month | Competent authority (national financial regulator) |
| **NIS2 Directive** | EU | Significant incident affecting essential/important entities | Early warning within 24 hours; incident notification within 72 hours; final report within 1 month | National CSIRT or competent authority |
| **SEC Cybersecurity Rules** | US (public companies) | Material cybersecurity incident | 4 business days after materiality determination | SEC (Form 8-K) |
| **SOC 2 (CC7.3/CC7.4)** | Global (service orgs) | Security incident affecting trust services criteria | Per contractual obligations with customers | Affected customers per agreement |

---

## Incident Type → Regulatory Trigger Mapping

| Incident Type | Likely Regulatory Triggers | Key Question |
|---|---|---|
| **Credential Compromise** | GDPR, CCPA, PIPEDA, NDB (if personal data accessed) | Was personal data accessible with the compromised credentials? |
| **Data Exfiltration (S3)** | GDPR, CCPA, HIPAA, PCI-DSS, PIPEDA, NDB, SEC | What data types were in the affected buckets? |
| **Ransomware** | GDPR (data unavailability = breach), HIPAA, NIS2, DORA | Was personal/health/financial data encrypted or exfiltrated? |
| **DDoS** | NIS2, DORA (if essential service), SOC 2 | Did the outage affect availability of regulated services? |
| **Insider Threat** | GDPR, CCPA, HIPAA (depending on data accessed) | What data did the insider access beyond their authorization? |
| **Root Account Takeover** | All applicable regulations (assume worst case) | Treat as full-scope breach until proven otherwise |
| **Cryptomining** | Generally NOT a notification trigger | Unless the attacker also accessed data (check lateral movement) |
| **CI/CD Compromise** | PCI-DSS (if cardholder environment), SOC 2 | Could the supply chain compromise have affected production data? |

---

## Key Principles

### 1. When in Doubt, Assume Notification is Required
It is better to notify early and update later than to miss a deadline. Most regulations allow for incomplete initial notifications with follow-up reports.

### 2. The Clock Starts at Awareness, Not Confirmation
For GDPR and most frameworks, the notification clock starts when you become **aware** of the breach — not when you've completed your investigation. "Awareness" typically means when you have a reasonable degree of certainty that a breach has occurred.

### 3. Document Everything
Regardless of whether notification is required, document:
- When the incident was detected
- When the incident was assessed
- The rationale for notification/non-notification decisions
- All communications with regulators and affected parties

### 4. Containment Does Not Eliminate Notification Obligations
Even if you contain an incident quickly, if personal data was accessed (even briefly), notification obligations may still apply.

---

## AWS-Specific Considerations

### Shared Responsibility
- AWS is responsible for security **of** the cloud (infrastructure)
- Customers are responsible for security **in** the cloud (their data, configurations, access)
- Regulatory notification for customer data breaches is the **customer's** responsibility
- AWS will notify customers if AWS infrastructure is compromised (per the [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/))

### AWS Artifact
Use [AWS Artifact](https://aws.amazon.com/artifact/) to access AWS compliance reports (SOC 2, PCI-DSS, ISO 27001) that may be needed for your regulatory response.

### AWS Security Incident Response Service
The [AWS Security Incident Response](https://aws.amazon.com/security-incident-response/) service can assist with evidence gathering and documentation that supports regulatory notification requirements.

---

## References

- [GDPR Full Text](https://gdpr-info.eu/)
- [CCPA/CPRA Text](https://oag.ca.gov/privacy/ccpa)
- [HIPAA Breach Notification Rule](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html)
- [PCI-DSS v4.0](https://www.pcisecuritystandards.org/)
- [PIPEDA Breach Reporting](https://www.priv.gc.ca/en/privacy-topics/business-privacy/safeguards-and-breaches/privacy-breaches/respond-to-a-privacy-breach-at-your-business/)
- [Australian NDB Scheme](https://www.oaic.gov.au/privacy/notifiable-data-breaches)
- [NIS2 Directive](https://digital-strategy.ec.europa.eu/en/policies/nis2-directive)
- [SEC Cybersecurity Disclosure Rules](https://www.sec.gov/rules/final/2023/33-11216.pdf)
- [DORA Regulation](https://www.digital-operational-resilience-act.com/)

---

> **Disclaimer:** This document is provided for informational purposes only and does not constitute legal advice. Regulatory requirements vary by jurisdiction, industry, data type, and contractual obligations. Always consult qualified legal counsel for specific notification decisions.
