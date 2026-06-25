# IRP-DoS: Denial of Service / Distributed Denial of Service

> **Playbook Version:** 2.1
> **Last Reviewed:** 2026-06-18
> **Status:** `Active`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-CredCompromise](IRP-CredCompromise.md) | [IRP-Ransomware](IRP-Ransomware.md) | [IRP-NetworkIntrusion](IRP-NetworkIntrusion.md) (Coming Soon) | [IRP-ResourceHijacking](IRP-ResourceHijacking.md) (Coming Soon)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks attempt to make AWS-hosted applications and services unavailable to legitimate users by overwhelming them with traffic or exploiting application-layer vulnerabilities. These attacks range from volumetric floods (Layer 3/4) that saturate network capacity, to protocol attacks that exhaust connection state tables, to sophisticated application-layer (Layer 7) attacks that target specific API endpoints or application logic. In AWS environments, DDoS attacks may target CloudFront distributions, Application Load Balancers, API Gateway endpoints, Route 53 hosted zones, or directly-exposed EC2 instances. The impact ranges from degraded performance to complete service unavailability, with potential cascading effects on dependent systems and significant financial exposure from auto-scaling costs.

### Out of Scope

This playbook does **not** cover:

- **Resource hijacking for cryptomining or botnet participation** — If compromised resources are generating outbound DoS traffic (your infrastructure as the attack source), see [IRP-ResourceHijacking](IRP-ResourceHijacking.md) (Coming Soon).
- **Credential compromise leading to service disruption** — If a threat actor uses stolen credentials to delete resources or modify configurations causing an outage, see [IRP-CredCompromise](IRP-CredCompromise.md).
- **Ransomware with availability impact** — If the availability loss is due to encryption of data or systems, see [IRP-Ransomware](IRP-Ransomware.md).
- **Network intrusion with lateral movement** — If the DoS is a diversion for active network intrusion, pivot to [IRP-NetworkIntrusion](IRP-NetworkIntrusion.md) (Coming Soon) once the intrusion is confirmed.

### Applicable Finding Types

| Source | Finding / Event Type | Severity |
|---|---|---|
| Amazon GuardDuty | `Backdoor:EC2/DenialOfService.Tcp` | HIGH |
| Amazon GuardDuty | `Backdoor:EC2/DenialOfService.Udp` | HIGH |
| Amazon GuardDuty | `Backdoor:EC2/DenialOfService.Dns` | HIGH |
| Amazon GuardDuty | `Backdoor:EC2/DenialOfService.UdpOnTcpPorts` | HIGH |
| Amazon GuardDuty | `Backdoor:EC2/DenialOfService.UnusualProtocol` | HIGH |
| Amazon GuardDuty | `Impact:EC2/PortSweep` | MEDIUM |
| Amazon GuardDuty | `Trojan:EC2/DGADomainRequest.B` | HIGH |
| Amazon GuardDuty | `Trojan:EC2/DNSDataExfiltration` | HIGH |
| AWS Shield Advanced | DDoS event detected (Layer 3/4 or Layer 7) | CRITICAL |
| AWS WAF | Rate-based rule triggered / Bot Control detection | MEDIUM |
| CloudWatch | ALB 5xx rate > threshold / Target response time spike | — |
| CloudWatch | CloudFront 5xx error rate > threshold | — |
| CloudWatch | API Gateway 429/5xx rate spike | — |
| VPC Flow Logs | Anomalous inbound traffic volume from multiple sources | — |
| CloudFront Access Logs | Request rate anomaly / geographic concentration | — |
| Route 53 | Health check failures across multiple endpoints | — |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list. Shield Advanced events are visible in the AWS Shield console and via CloudWatch metrics in the `AWS/DDoSProtection` namespace.

### Severity Classification

| Priority | Criteria |
|---|---|
| **P1 — Critical** | Production service fully unavailable, revenue-impacting, or attack sustained and escalating despite initial mitigations; Shield Advanced SRT engagement required |
| **P2 — High** | Significant performance degradation to production services, attack confirmed and ongoing, or application-layer attack bypassing existing WAF rules |
| **P3 — Medium** | Elevated traffic detected triggering rate-based rules, minor latency increase, auto-scaling absorbing load but costs escalating abnormally |
| **P4 — Low** | Shield Advanced detected and auto-mitigated a volumetric event with no customer-visible impact, or reconnaissance-level probing detected |

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

### 1.1 Recommended AWS Service Configurations

The following services each contribute to your ability to detect, absorb, and respond to DoS/DDoS attacks. None are strictly required, but DDoS resilience is cumulative — each layer you add reduces the potential impact and shortens time-to-mitigation. The more you have enabled, the more likely attacks are absorbed automatically without requiring human intervention.

- [ ] **AWS Shield Standard** enabled (automatic for all AWS accounts) — provides always-on network-layer protection for resources behind CloudFront, Route 53, and Global Accelerator
- [ ] **AWS Shield Advanced** enabled on critical resources (CloudFront, ALB, NLB, Elastic IP, Global Accelerator, Route 53 hosted zones) — adds enhanced detection, real-time attack visibility, SRT access, and cost protection
- [ ] **AWS Shield Advanced automatic application-layer DDoS mitigation** enabled — allows Shield to create WAF rules automatically based on observed attack patterns
- [ ] **AWS WAF** deployed on CloudFront distributions, ALBs, and API Gateway stages — required for application-layer (Layer 7) protection
- [ ] **WAF rate-based rules** configured with appropriate thresholds per endpoint — the first line of defense against HTTP floods
- [ ] **WAF Bot Control** managed rule group enabled (targeted or common level) — detects and blocks automated traffic from known bot frameworks
- [ ] **WAF managed rule groups** enabled (Amazon IP Reputation List, Anonymous IP List) — blocks traffic from known-bad sources without manual rule management
- [ ] **CloudFront** configured with origin access control (OAC) to protect origins from direct access — prevents threat actors from bypassing edge protections
- [ ] **Route 53 health checks** configured for all critical endpoints — enables Shield Advanced proactive engagement and CloudFront failover
- [ ] **VPC Flow Logs** enabled for all production VPCs (sent to S3 for Athena analysis) — provides network-layer visibility for volumetric attack analysis
- [ ] **CloudWatch alarms** configured for: ALB 5xx rate, target response time, request count, CloudFront error rate — ensures rapid detection when attacks impact availability
- [ ] **Auto Scaling groups** configured with appropriate minimum, maximum, and scaling policies — absorbs traffic spikes while capping cost exposure
- [ ] **Amazon GuardDuty** enabled in all regions with findings exported to Security Hub — detects if your resources are *generating* outbound DoS traffic (indicates compromise)
- [ ] **AWS Global Accelerator** deployed for critical internet-facing applications — provides DDoS resilience at edge with automatic failover
- [ ] **CloudFront access logging** enabled and delivered to S3 — required for post-incident analysis of request patterns
- [ ] **WAF logging** enabled and delivered to S3 or CloudWatch Logs — required to assess rule effectiveness during and after attacks
- [ ] **Shield Advanced proactive engagement** configured (requires Route 53 health checks) — SRT contacts you automatically when health checks fail during detected events

> 🤖 **Automation opportunity:** Use AWS Firewall Manager to centrally deploy WAF rules and Shield Advanced protections across all accounts in your organization. EventBridge rules can trigger automatic WAF rule updates when Shield Advanced detects an event.
>
> 📖 **Reference:** [SEC10-BP06 Pre-deploy tools](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_deploy_tools.html) — AWS Well-Architected Framework recommends pre-deploying investigation and response tooling so capabilities are available immediately when needed.

### 1.2 IAM & Access Prerequisites

Effective incident response depends on having the right access available *before* an incident occurs. For DoS/DDoS specifically, containment actions (WAF rule deployment, NACL changes, scaling adjustments) must happen in minutes — provisioning access during an active attack wastes the time you least have. The following recommendations align with [SEC10-BP05 Pre-provision access](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_provision_access.html) from the AWS Well-Architected Framework.

- [ ] **Break-glass IAM role** exists with permissions to: modify WAF rules, update Network ACLs, modify security groups, adjust Auto Scaling policies, and engage Shield Response Team (SRT) — pre-tested and documented
- [ ] **IR team members can assume the break-glass role** with MFA from a trusted account — validate this works at least quarterly
- [ ] **Shield Advanced SRT access is pre-authorized** (IAM role for SRT created and associated with Shield Advanced subscription) — required for SRT to modify your WAF rules during engagement
- [ ] **Access to AWS Security Incident Response console** confirmed (if subscribed) — verify case creation workflow before you need it
- [ ] **WAF rule templates** (emergency rate-limit, geographic block, IP blocklist) pre-created and tested — deploy in seconds during an attack rather than authoring JSON under pressure
- [ ] **Network ACL emergency rules** documented and tested (deny rules for known-bad CIDR ranges) — understand the 20-rule-per-direction limit
- [ ] **AWS Support Enterprise or Business plan** active (required for SRT engagement) — verify plan level before you need it

### 1.3 Communication & Escalation

Clear communication paths reduce confusion during high-pressure incidents. DoS events are particularly time-sensitive — service is actively degraded while you coordinate. Define who needs to be involved, at what severity threshold, and through which channel *before* you need them.

> 📋 Do not include names in this playbook. Use roles only. Maintain a separate, access-controlled contact list with current names, phone numbers, and escalation preferences.

| Role | Responsibility | When to Engage |
|---|---|---|
| IR Lead | Overall incident coordination, status updates, SRT liaison | All severity levels — first notified |
| Account Owner | Business context, authorization for traffic-blocking actions | P1–P3, or when containment may block legitimate traffic |
| Application Owner | Impact assessment, identification of legitimate traffic patterns | When distinguishing attack from legitimate traffic spikes |
| Network Engineer | WAF rule deployment, Network ACL changes, traffic analysis | All severity levels — executes containment |
| Legal / Compliance | Regulatory notification for availability SLA breaches | P1–P2, or when regulated service SLAs are breached |
| Communications | Customer-facing status page updates, internal messaging | P1–P2, or when customer-visible impact exceeds 15 minutes |
| AWS Shield Response Team (SRT) | Custom DDoS mitigation via Shield Advanced console | P1/P2, Shield Advanced subscribers only |
| AWS CIRT | Technical assistance via AWS Support case or Security Incident Response service | P1/P2, when concurrent compromise suspected or attack characterization needed |

**Escalation path:**

1. **Detection:** Automated alert (Shield Advanced, CloudWatch alarm, WAF rate-based rule, Route 53 health check) or human report triggers initial notification.
2. **Triage (IR Lead, < 10 min):** IR Lead assesses severity using [Section 2.3](#23-severity-determination). Determines if service is impacted and whether existing mitigations are holding.
3. **Severity-based escalation:**
   - **P1/P2:** IR Lead engages Network Engineer immediately for containment. Engages SRT in parallel (Shield Advanced subscribers). Notifies Account Owner and Communications. Opens AWS Support case if CIRT assistance needed.
   - **P3/P4:** IR Lead monitors with Network Engineer. Prepares containment actions. Escalates to P2 if attack intensifies or auto-mitigation fails.
4. **Status updates:** IR Lead provides updates to stakeholders every 15 minutes (P1), every 30 minutes (P2), or at key milestones (P3/P4).

> 📖 **Reference:** [SEC10-BP01 Identify key personnel and external resources](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_identify_personnel.html) — recommends identifying and documenting internal and external resources and contact information ahead of time.

### 1.4 Game Day Guidance

Practicing incident response before a real incident occurs builds muscle memory, identifies gaps in tooling and access, and validates that escalation paths work. DDoS response in particular benefits from practice because containment involves multiple AWS services (WAF, Shield, NACLs, Auto Scaling) and coordination with external teams (SRT). Teams that exercise regularly contain incidents faster and make fewer false-positive blocking decisions.

Recommended testing cadence: **Semi-annually** (this is a P1-capable scenario with high likelihood).

Suggested tabletop scenario:
> *"Your organization's primary API Gateway endpoint serving a customer-facing mobile application begins returning 429 and 503 errors. CloudWatch shows request rates have increased 50x in the last 10 minutes, originating from thousands of unique IP addresses. The requests are valid HTTP POST calls to your /api/v2/search endpoint with randomized but syntactically correct payloads. Your existing WAF rate-based rule (2,000 requests per 5 minutes per IP) is not triggering because each source IP stays below the threshold. Application Auto Scaling is launching new tasks but the database connection pool is saturating. Customer support tickets are arriving."*

**Practice resources (no paid service or support plan required):**

- [AWS CIRT Incident Response Workshops](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-release-of-five-publicly-available-workshops/) — free, hands-on workshops covering incident response scenarios. Deployable in any AWS account.
- [Incident Response Playbooks Workshop (GitHub)](https://github.com/aws-samples/aws-incident-response-playbooks-workshop/) — hands-on workshop for building and testing playbooks.
- [AWS Security Workshops catalog](https://workshops.aws/categories/Security) — broader collection of security-focused hands-on labs.
- [AWS Best Practices for DDoS Resiliency (Whitepaper)](https://docs.aws.amazon.com/whitepapers/latest/aws-best-practices-ddos-resiliency/aws-best-practices-ddos-resiliency.html) — architecture patterns that reduce DDoS exposure.

> 📖 **Reference:** [SEC10-BP04 Develop and test security incident response playbooks](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_playbooks.html) — recommends creating and regularly testing playbooks to verify response processes.

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Confirm whether an incident has occurred, scope its impact, and gather evidence for containment and investigation.

### 2.1 Initial Triage Questions

Not every traffic spike is an attack. Legitimate events (product launches, marketing campaigns, viral content, partner integrations) can produce traffic patterns that resemble DDoS. These triage questions help distinguish attacks from organic spikes and determine appropriate response urgency.

- [ ] What is the traffic pattern? (Sudden spike from many sources, gradual increase, or single-source saturation)
- [ ] What is the suspected vector? (Volumetric Layer 3/4, protocol attack, or application-layer Layer 7)
- [ ] Which resources are targeted? (CloudFront distribution, ALB, API Gateway, Route 53, direct EC2/EIP)
- [ ] Is the service currently degraded or fully unavailable?
- [ ] Is Shield Advanced detecting and reporting the event? (Check AWS Shield console)
- [ ] Are existing WAF rules and rate-based rules triggering? (Check WAF metrics)
- [ ] Is Auto Scaling responding? Is it helping or creating cost exposure?
- [ ] Can you distinguish attack traffic from legitimate traffic? (User agents, geographic origin, request patterns, correlation with business events)
- [ ] Is there a known business reason for elevated traffic? (Marketing campaign, partner launch, media coverage)
- [ ] Is this a diversion for another attack? (Check GuardDuty for concurrent credential or data access findings)
- [ ] Are Route 53 health checks failing? Is proactive engagement triggered?
- [ ] What is the financial exposure? (Auto Scaling costs, data transfer costs)

**If service is fully unavailable AND attack is bypassing existing mitigations → P1 immediately.**

### 2.2 Evidence Documentation

> ⚠️ **Prioritize mitigation over evidence collection for DoS incidents.** Unlike credential compromise, the primary goal is restoring availability. Collect evidence in parallel with containment actions — do not delay mitigation to gather logs.

| Evidence Type | How to Collect | Where to Store |
|---|---|---|
| Shield Advanced event details | Shield console → Events tab / `aws shield describe-attack` | IR ticket |
| WAF sampled requests | WAF console → Web ACL → Sampled requests | Forensic S3 bucket |
| WAF logs (full) | S3 bucket or CloudWatch Logs (if WAF logging enabled) | Forensic S3 bucket |
| CloudFront access logs | S3 bucket (standard logging) or real-time logs (Kinesis) | Forensic S3 bucket |
| VPC Flow Logs | S3 or CloudWatch Logs | Forensic S3 bucket |
| CloudWatch metrics snapshot | CloudWatch console → relevant dashboards | IR ticket (screenshots + metric export) |
| ALB access logs | S3 bucket (if ALB access logging enabled) | Forensic S3 bucket |
| API Gateway execution logs | CloudWatch Logs | Forensic S3 bucket |
| GuardDuty findings (concurrent) | GuardDuty console → export findings | Forensic S3 bucket |
| Auto Scaling activity | `aws autoscaling describe-scaling-activities` | IR ticket |

**Key CloudWatch Metrics to Monitor:**

| Metric | Namespace | Indicates |
|---|---|---|
| `DDoSDetected` | `AWS/DDoSProtection` | Shield Advanced has detected an attack |
| `DDoSAttackBitsPerSecond` | `AWS/DDoSProtection` | Volumetric attack magnitude |
| `DDoSAttackRequestsPerSecond` | `AWS/DDoSProtection` | Application-layer attack rate |
| `HTTPCode_ELB_5XX_Count` | `AWS/ApplicationELB` | Load balancer overwhelmed |
| `TargetResponseTime` | `AWS/ApplicationELB` | Backend latency (saturation indicator) |
| `RequestCount` | `AWS/ApplicationELB` | Total request volume |
| `5xxErrorRate` | `AWS/CloudFront` | Origin or CloudFront errors |
| `Requests` | `AWS/CloudFront` | Total CloudFront request volume |
| `4xxErrorRate` | `AWS/ApiGateway` | Rate limiting / throttling active |
| `Count` | `AWS/ApiGateway` | API request volume |
| `BlockedRequests` | `AWS/WAFV2` | WAF rules actively blocking |
| `CountedRequests` | `AWS/WAFV2` | WAF rules matching (count mode) |
| `HealthCheckStatus` | `AWS/Route53` | Endpoint availability |

**Investigation Queries (Athena):**

For detailed log analysis queries (CloudFront, WAF, VPC Flow Logs), see [`resources/athena-queries-dos.sql`](resources/athena-queries-dos.sql). Queries cover:

- Top source IPs by request volume
- Application-layer attack pattern detection
- WAF rule effectiveness analysis
- Volumetric attack source identification
- Protocol and port distribution analysis

### 2.3 Severity Determination

| Confirmed? | Priority Assignment |
|---|---|
| Service fully unavailable, attack sustained and escalating, existing mitigations ineffective | P1 |
| Significant degradation confirmed, attack ongoing, WAF rules partially effective | P2 |
| Elevated traffic detected, rate-based rules triggering, minor latency increase, auto-scaling absorbing | P3 |
| Shield Advanced auto-mitigated with no customer impact, or low-level probing detected | P4 |

### 2.4 Getting Help from AWS

> 📌 **If your organization has the AWS Security Incident Response service enabled, or has AWS Support, you can request assistance from the AWS Customer Incident Response Team (CIRT).**

**P1 — Service fully unavailable, attack sustained:**

Engage all available AWS resources immediately:

- **Shield Advanced SRT:** Navigate to the [AWS Shield console](https://console.aws.amazon.com/shield/), review the active event, select **Contact the SRT**. SRT can directly modify your WAF rules and create custom mitigations.
- **AWS Support:** Open a case with Critical severity. Include Shield event ID, affected resources, and current mitigation status.
- **AWS Security Incident Response service (if subscribed):** Sign into [AWS Security Incident Response](https://console.aws.amazon.com/security-ir/) via the console, choose **Create Case**, select **Resolve case with AWS**, and choose **Active Security Incident**.

**P2 — Significant degradation, attack confirmed:**

- **Shield Advanced SRT:** Engage if auto-mitigation is insufficient or if you need assistance characterizing application-layer attack patterns.
- **AWS CIRT:** Engage via support case if you suspect the DoS is covering concurrent credential compromise or data access activity. CIRT can help correlate CloudTrail activity with the DDoS event timeline.
- **AWS Support:** Open a case with High severity for guidance on WAF rule optimization.

**P3 — Elevated traffic, unclear if attack or organic spike:**

- **AWS CIRT:** Can help determine whether elevated traffic is an attack or legitimate organic spike by analyzing traffic patterns, source reputation, and request characteristics. Open a support case describing the traffic anomaly.
- **Shield Advanced:** Review the Shield console for event classification. Shield Advanced distinguishes between DDoS attacks and legitimate traffic spikes.

> 📌 You do not need the Security Incident Response service to get help from AWS CIRT. All AWS customers can request CIRT assistance through a support case, regardless of support plan level.
>
> 🤖 **Automation opportunity:** Configure Shield Advanced proactive engagement so the SRT contacts you automatically when Route 53 health checks fail during a detected DDoS event. This eliminates the need to manually engage during a P1.

---

## Part 3 — Contain

> **CSF 2.0 Function:** Respond (Contain)
> **Goal:** Restore availability by mitigating attack traffic while preserving legitimate user access.

### 3.1 Containment Decision

For DoS/DDoS incidents, containment is almost always urgent. Unlike credential compromise where you may observe before acting, availability loss is immediate customer impact. The decision tree focuses on *how aggressively* to contain rather than *whether* to contain.

```text
Is the service currently unavailable or severely degraded?
│
├── YES (P1/P2 — active impact)
│     └── Proceed immediately to 3.2 — accept risk of blocking some legitimate traffic
│         └── Engage SRT in parallel if Shield Advanced subscriber
│
└── NO (P3/P4 — elevated traffic, no impact yet)
      └── Monitor closely, prepare containment actions
            Is the attack escalating?
            ├── YES → Proceed to 3.2 proactively
            └── NO  → Continue monitoring, document patterns for future rule creation
```

### 3.2 Containment Actions

> `[IR Lead]` coordinates. `[Network Engineer]` executes. `[Account Owner]` authorizes actions that may block legitimate traffic.

**Layer 3/4 Volumetric Attack Containment:**

1. **Verify Shield Advanced auto-mitigation is active**
   Check the Shield console for active mitigations. For resources protected by Shield Advanced, AWS automatically applies network-layer mitigations.

   ```bash
   # Check active attacks and mitigations
   aws shield describe-attack --attack-id <attack-id>

   # List all detected events in the last hour
   aws shield list-attacks \
     --start-time "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" \
     --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
   ```

2. **Engage the Shield Response Team (SRT) — P1/P2**
   If auto-mitigation is insufficient, engage the SRT via the Shield console or AWS Support case with Critical severity. Provide: Shield event ID, affected resources, traffic characteristics observed, and desired mitigation outcome.

3. **Deploy emergency Network ACL rules (direct-to-origin attacks)**
   If the attack bypasses CloudFront/ALB and targets resources directly, add deny rules for the largest identified source CIDR blocks. NACLs have a 20-rule-per-direction limit — prioritize the highest-volume sources identified from VPC Flow Log analysis.

**Application-Layer (Layer 7) Attack Containment:**

1. **Deploy WAF rate-based rule with aggressive threshold**

   ```bash
   # Create an emergency rate-based rule (lower threshold than normal)
   aws wafv2 update-web-acl \
     --name "production-web-acl" \
     --scope REGIONAL \
     --id <web-acl-id> \
     --lock-token <lock-token> \
     --default-action '{"Allow":{}}' \
     --rules '[
       {
         "Name": "EmergencyRateLimit",
         "Priority": 1,
         "Statement": {
           "RateBasedStatement": {
             "Limit": 300,
             "AggregateKeyType": "IP"
           }
         },
         "Action": {"Block":{}},
         "VisibilityConfig": {
           "SampledRequestsEnabled": true,
           "CloudWatchMetricsEnabled": true,
           "MetricName": "EmergencyRateLimit"
         }
       }
     ]'
   ```

2. **Deploy geographic restriction (if attack is geographically concentrated)**
   If traffic analysis shows attack sources concentrated in specific countries that don't serve your legitimate user base, deploy a WAF geographic match rule or CloudFront geographic restriction. Use WAF for granular control (per-endpoint), or CloudFront restrictions for blanket blocking.

3. **Deploy WAF IP blocklist for identified attack sources**
   Create or update a WAF IP set with the highest-volume attack source CIDRs identified from log analysis. Reference the IP set in a WAF block rule with high priority.

4. **Adjust Auto Scaling to manage cost exposure**
   Set a maximum capacity ceiling to prevent runaway scaling costs while maintaining enough capacity for legitimate traffic. For ECS services, adjust the scalable target max-capacity similarly.

5. **Enable CloudFront origin failover (if origin is overwhelmed)**
   If the primary origin is saturated, configure CloudFront to fail over to a static maintenance page or cached content served from S3. This preserves some user experience while protecting the origin.

> 🤖 **Automation opportunity:** EventBridge rule triggered by Shield Advanced `DDoSDetected` metric can automatically invoke a Lambda function that deploys pre-configured WAF rate-based rules and notifies the IR team via SNS.

```json
// EventBridge rule pattern for Shield Advanced DDoS detection
{
  "source": ["aws.shield"],
  "detail-type": ["AWS Shield DDoS Attack"],
  "detail": {
    "eventTypeCode": ["AWS_SHIELD_DDOS_ATTACK"]
  }
}
```

### 3.3 Document Containment Actions

Record all containment actions taken for post-incident review and regulatory compliance:

- [ ] WAF logs are being captured for the duration of the attack (verify logging is not throttled)
- [ ] CloudFront access logs are being delivered (check for delivery delays)
- [ ] VPC Flow Logs are active and capturing (verify no gaps)
- [ ] Shield Advanced attack details exported (`aws shield describe-attack`)
- [ ] CloudWatch metrics exported for the attack window (ALB, CloudFront, WAF, Shield namespaces)
- [ ] WAF sampled requests captured (console → Web ACL → Sampled requests)
- [ ] Screenshots of Shield console event timeline preserved
- [ ] Document: what action was taken, when (UTC timestamp), by whom (role), and authorization received

---

## Part 4 — Eradicate & Recover

> **CSF 2.0 Function:** Respond (Eradicate) · Recover
> **Goal:** Confirm the attack has subsided, remove emergency mitigations where appropriate, validate service health, and harden against recurrence.

Unlike credential compromise where eradication involves removing threat-actor-created persistence, DoS eradication is about confirming the attack has ended and ensuring your environment is hardened against recurrence. Do not rush to relax emergency mitigations — attacks commonly resume after brief pauses to test whether defenses have been lowered.

### 4.1 Root Cause Identification

> `[IR Lead]` owns this step. Document findings in the IR ticket in real time.

Determine the root cause and attack characteristics before relaxing mitigations. Common root causes for DoS/DDoS in AWS environments:

- **Publicly exposed origin** — Application Load Balancer or EC2 instance directly accessible without CloudFront/WAF protection, allowing threat actors to bypass edge mitigations
- **Insufficient rate limiting** — No WAF rate-based rules, or thresholds set too high to catch distributed attacks
- **Application-layer vulnerability** — Expensive API endpoint (complex database query, large response payload) exploitable at low request rates
- **Missing Shield Advanced protection** — Critical resources not enrolled in Shield Advanced, limiting auto-mitigation capability
- **DNS amplification exposure** — Open resolvers or misconfigured Route 53 settings enabling reflection attacks
- **Inadequate scaling configuration** — Auto Scaling maximum too low (causing unavailability) or too high (causing cost explosion)
- **Lack of geographic or bot controls** — No geographic restrictions or bot detection on endpoints that don't serve global traffic

Use evidence collected in Part 2 to characterize the attack vector, peak magnitude, duration, and source distribution.

### 4.2 Eradication Actions

> `[IR Lead]` coordinates. `[Network Engineer]` executes. `[Account Owner]` approves changes to production resources.

1. **Confirm attack has subsided**
   Monitor Shield Advanced metrics and WAF block rates for at least 30 minutes of sustained normal levels before declaring the attack over. Verify in the Shield console that no active events are reported, and confirm CloudWatch metrics (request count, 5xx rate, target response time) have returned to baseline.

2. **Gradually relax emergency mitigations**
   Do not remove all emergency rules simultaneously. Relax in stages and monitor for attack resumption:
   - Stage 1: Increase emergency rate-limit threshold (e.g., 300 → 1,000 per 5 min) — monitor for 30 minutes
   - Stage 2: Remove geographic blocks (if legitimate traffic from those regions is expected) — monitor for 1 hour
   - Stage 3: Remove emergency IP blocklist entries (after 24–48 hours of no activity from those sources)
   - Stage 4: Remove emergency Network ACL deny rules

3. **Convert effective emergency rules to permanent protections**
   If emergency WAF rules proved effective, create production-grade versions:
   - [ ] Rate-based rules with appropriate long-term thresholds
   - [ ] Bot Control rules for endpoints that were targeted
   - [ ] Custom rules matching the specific attack signature (user agent, URI pattern, header anomalies)

4. **Verify no secondary compromise occurred**
   DDoS attacks are sometimes used as a diversion. Check for:
   - [ ] Unusual IAM activity during the attack window (credential compromise under cover of DoS)
   - [ ] Unauthorized resource creation or configuration changes
   - [ ] Data access events that occurred while the team was focused on availability
   - [ ] New GuardDuty findings unrelated to the DoS event

> 🤖 **Automation opportunity:** Create an EventBridge rule that triggers when Shield Advanced reports attack mitigation complete, automatically adjusting WAF rate-based rule thresholds back to normal levels after a configurable cool-down period.

### 4.3 Recovery Actions

1. **Restore normal Auto Scaling configuration**

   ```bash
   # Return Auto Scaling to normal parameters
   aws autoscaling update-auto-scaling-group \
     --auto-scaling-group-name "production-asg" \
     --max-size <normal-max> \
     --desired-capacity <normal-desired>
   ```

2. **Validate service health**
   - [ ] All Route 53 health checks passing
   - [ ] ALB target group healthy host count at expected level
   - [ ] Application response times within normal range
   - [ ] Error rates (4xx, 5xx) returned to baseline
   - [ ] Customer-facing functionality confirmed operational (synthetic monitoring)

3. **Harden against recurrence**
   - [ ] Enroll all internet-facing resources in Shield Advanced (if not already)
   - [ ] Enable Shield Advanced automatic application-layer DDoS mitigation
   - [ ] Configure proactive engagement (requires Route 53 health checks)
   - [ ] Deploy WAF Bot Control on targeted endpoints
   - [ ] Implement CloudFront origin access control to prevent direct origin access
   - [ ] Review and lower rate-based rule thresholds based on attack analysis
   - [ ] Deploy AWS Global Accelerator for critical endpoints (provides additional DDoS resilience)
   - [ ] Implement request validation (API schema validation, payload size limits) to reduce application-layer attack surface
   - [ ] Configure CloudFront origin shield to reduce origin load

### 4.4 Resolution Confirmation

Confirm the environment is stable before declaring the incident resolved.

- [ ] Attack traffic has ceased for at least 2 hours (monitor Shield Advanced metrics)
- [ ] All emergency mitigations either removed or converted to permanent rules
- [ ] Application performance metrics within normal range for at least 1 hour
- [ ] Route 53 health checks all passing
- [ ] Auto Scaling configuration returned to normal parameters
- [ ] No secondary compromise indicators detected (GuardDuty, CloudTrail review)
- [ ] Customer-facing status page updated (if previously communicated)
- [ ] Shield Advanced SRT case closed (if engaged)
- [ ] AWS Security Incident Response case updated / closed (if applicable)
- [ ] Cost impact assessed (data transfer, Auto Scaling, WAF request charges)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Learn from this incident to reduce the likelihood and impact of future occurrences.

Post-incident activity for DoS events is particularly valuable because DDoS attacks tend to recur. Threat actors who successfully disrupt a target often return — and application-layer attacks in particular evolve to bypass the mitigations you deployed. Investing in post-incident hardening directly reduces future impact.

### 5.1 Timeline Reconstruction

Document the full incident timeline. Complete this within 24–48 hours while memory is fresh.

| Timestamp (UTC) | Event | Source / Evidence | Actor |
|---|---|---|---|
| YYYY-MM-DD HH:MM | Attack traffic begins | CloudWatch metrics / VPC Flow Logs | Threat actor |
| YYYY-MM-DD HH:MM | Shield Advanced detects event | Shield console | AWS |
| YYYY-MM-DD HH:MM | CloudWatch alarm fires / health check fails | CloudWatch / Route 53 | AWS |
| YYYY-MM-DD HH:MM | IR team notified | On-call alert | Automated |
| YYYY-MM-DD HH:MM | SRT engaged (if applicable) | Shield console | IR Lead |
| YYYY-MM-DD HH:MM | Emergency WAF rules deployed | WAF console / CLI | Network Engineer |
| YYYY-MM-DD HH:MM | Service availability restored | CloudWatch metrics | — |
| YYYY-MM-DD HH:MM | Attack traffic subsides | Shield Advanced | — |
| YYYY-MM-DD HH:MM | Emergency mitigations relaxed | WAF / NACL changes | Network Engineer |
| YYYY-MM-DD HH:MM | Incident declared resolved | IR ticket | IR Lead |

**Key metrics to capture:**

| Metric | Value | Why It Matters |
|---|---|---|
| Time to Detect (TTD) | *HH:MM from attack start to first alert* | Measures alarm and monitoring effectiveness |
| Time to Notify (TTN) | *HH:MM from alert to IR team notified* | Measures alerting pipeline reliability |
| Time to Mitigate (TTM) | *HH:MM from notification to service restored* | Measures containment speed — primary DoS KPI |
| Time to Resolve (TTR) | *HH:MM from mitigation to incident closed* | Measures full lifecycle including hardening |
| Total Incident Duration | *HH:MM* | Overall impact window for SLA calculations |
| Peak Attack Magnitude | *Gbps (volumetric) or requests/sec (Layer 7)* | Informs capacity planning and Shield engagement thresholds |
| Service Unavailability Duration | *HH:MM of customer-visible impact* | Direct input to SLA breach assessment |
| Financial Impact | *Estimated cost (data transfer, scaling, WAF charges)* | Justifies Shield Advanced cost protection claims |
| Affected Resources | *Count and type* | Informs Shield Advanced enrollment decisions |
| Legitimate Traffic Blocked | *Estimated false positive rate during mitigation* | Measures containment precision — informs rule tuning |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4.

Discussion questions:

1. What type of attack was this? (Volumetric, protocol, application-layer, or combination)
2. Were the targeted resources protected by Shield Advanced? If not, why not?
3. How quickly was the attack detected? Could detection have been faster with better alarming?
4. Did Shield Advanced auto-mitigation work effectively? If not, what was the gap?
5. Were WAF rules effective? What rules would have caught this attack earlier?
6. Did the SRT engagement process work smoothly? Were pre-authorizations in place?
7. Was legitimate traffic blocked during mitigation? How can we reduce false positives?
8. Did Auto Scaling help or hurt? (Absorbed load vs. created cost exposure)
9. Was this attack a diversion? Did we check for concurrent security events?
10. What is the total financial impact (direct costs + revenue loss + remediation effort)?
11. What single architectural change would most reduce our exposure to this attack type?
12. Was our preparation adequate? Did we have the right tools, access, and runbooks ready, or did we waste time provisioning during the incident?

### 5.3 Detection Gap Analysis

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| *(e.g., No alarm on API Gateway 5xx rate)* | *(CloudWatch alarm not configured)* | *(Create alarm at 5% 5xx threshold)* | | |
| *(e.g., Shield Advanced not on ALB)* | *(Resource not enrolled)* | *(Enroll all internet-facing ALBs)* | | |
| *(e.g., WAF rate-based rule too permissive)* | *(Threshold set at 10,000/5min)* | *(Lower to 2,000/5min per IP)* | | |
| *(e.g., No bot detection on API endpoint)* | *(Bot Control not enabled)* | *(Enable targeted Bot Control)* | | |
| *(e.g., Origin directly accessible)* | *(No origin access control)* | *(Deploy CloudFront OAC, restrict origin SG)* | | |

### 5.4 Playbook Update Checklist

- [ ] Were triage questions sufficient for this attack type? Add/remove as needed.
- [ ] Were the containment actions effective? Update CLI commands and thresholds.
- [ ] Were any new attack patterns observed? Document for future detection rules.
- [ ] Were automation opportunities identified? Add EventBridge/Lambda stubs.
- [ ] Were severity criteria accurate? Adjust if incidents were under- or over-classified.
- [ ] Were SRT engagement procedures smooth? Update if process gaps found.
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

### 5.5 Shield Advanced Cost Protection

> 📌 For Shield Advanced subscribers: If the attack caused scaling charges, you may be eligible for cost protection credits.

- [ ] Review the [Shield Advanced cost protection eligibility](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-cost-protection.html)
- [ ] Document scaling charges attributable to the DDoS event
- [ ] Submit cost protection request via AWS Support within 15 days of the billing cycle

---

## Appendix A — Investigation Resources

Athena queries for CloudFront access logs, WAF logs, VPC Flow Logs, and CloudWatch Logs Insights are maintained in a companion file for easier reuse and version control:

📄 **[`resources/athena-queries-dos.sql`](resources/athena-queries-dos.sql)**

The file contains queries for:

- **CloudFront:** Top source IPs, application-layer attack pattern detection, User-Agent fingerprinting
- **WAF:** Blocked/counted request analysis, rate-based rule effectiveness
- **VPC Flow Logs:** Volumetric attack source identification, protocol/port distribution
- **CloudWatch Logs Insights:** ALB request patterns causing backend saturation
- **GuardDuty:** CLI reference for listing DoS-related findings

> 📌 Replace placeholder values (dates, timestamps, target IPs, table names) before running queries. See the file header for prerequisites.

---

## Appendix B — Regulatory & Compliance Considerations

> `[Legal / Compliance]` owns this section during an active incident.

See [Regulatory Context](../REGULATORY_CONTEXT.md) for the full notification obligation matrix by regulation and incident type.

**Quick reference for DoS/DDoS scenarios:**

| Regulation | Trigger Condition | Timeframe |
|---|---|---|
| NIS2 Directive (EU) | Significant incident affecting availability of essential/important services; service disruption exceeding defined thresholds | 24-hour early warning to CSIRT, 72-hour incident notification, 1-month final report |
| DORA (EU Financial Sector) | Major ICT-related incident affecting availability of critical financial services | Initial notification without undue delay, intermediate report within 1 week, final report within 1 month |
| GDPR Art. 33/34 | Personal data unavailability constituting a breach (if availability loss affects data subject rights) | 72 hours to supervisory authority (if risk to data subjects) |
| SOC 2 (Trust Services Criteria) | Availability commitment breach affecting customer SLAs | Per contractual obligations; document in SOC 2 reporting |
| PCI DSS v4.0 (Req. 12.10) | Service disruption affecting cardholder data environment availability | Per incident response plan; document and report per acquiring bank requirements |
| FedRAMP (US Federal) | Significant availability incident affecting federal information systems | US-CERT notification within 1 hour for significant incidents |
| APRA CPS 234 (Australia) | Material information security incident affecting availability | Notify APRA within 72 hours; notify affected persons as soon as practicable |

> ⚠️ For NIS2 and DORA: The clock starts at **awareness** of the significant impact, not when the attack begins. Availability incidents that breach SLA thresholds are reportable even without data compromise. When in doubt, assume notification is required and consult Legal immediately.
>
> 📌 **Shield Advanced subscribers:** AWS provides attack forensics reports that can support regulatory notification requirements. Request these from the SRT during or after engagement.

---

## Appendix C — Automation Hooks

### EventBridge Rules for Automated Response

**Rule 1: Shield Advanced DDoS Detection → WAF Emergency Rate Limit**

```json
{
  "Source": ["aws.shield"],
  "DetailType": ["AWS Health Event"],
  "Detail": {
    "eventTypeCode": ["AWS_SHIELD_DDOS_ATTACK_DETECTED"],
    "service": ["SHIELD"]
  }
}
```

Target: Lambda function that deploys pre-configured emergency WAF rate-based rule and sends SNS notification to IR team.

**Rule 2: Route 53 Health Check Failure → IR Team Notification**

```json
{
  "Source": ["aws.route53"],
  "DetailType": ["Route 53 Health Check Status Changed"],
  "Detail": {
    "CurrentStatus": ["UNHEALTHY"],
    "PreviousStatus": ["HEALTHY"]
  }
}
```

Target: SNS topic → IR team on-call pager + Slack channel.

**Rule 3: CloudWatch Composite Alarm → WAF Rule Tightening**

Configure a CloudWatch composite alarm combining:

- ALB 5xx rate > 10% for 2 consecutive periods
- ALB request count > 5x baseline for 2 consecutive periods
- Target response time > 5 seconds for 2 consecutive periods

Target: Step Functions workflow that:

1. Lowers WAF rate-based rule threshold
2. Enables WAF Bot Control (if not already active)
3. Creates Security Hub custom finding
4. Notifies IR team

### Shield Advanced Proactive Engagement

When configured, the SRT will automatically contact your designated operations team when:

- A Shield Advanced DDoS event is detected AND
- Associated Route 53 health checks transition to UNHEALTHY

**Setup requirements:**

1. Route 53 health checks associated with Shield Advanced protected resources
2. Emergency contact list configured in Shield Advanced settings
3. Proactive engagement feature enabled in Shield Advanced console

Configure these settings via the [Shield Advanced console](https://console.aws.amazon.com/shield/) under **Proactive engagement** and **Contacts**. Ensure health checks are associated with each protected resource under **Protected resources → Health check association**.

---

## Appendix D — Attack Type Reference

### Layer 3/4 (Volumetric & Protocol Attacks)

| Attack Type | Description | Primary AWS Mitigation |
|---|---|---|
| UDP Flood | High-volume UDP packets to saturate bandwidth | Shield Standard/Advanced (automatic) |
| SYN Flood | TCP SYN packets exhausting connection state | Shield Standard/Advanced (automatic) |
| DNS Amplification | Spoofed DNS queries generating large responses | Shield Advanced + Route 53 resilience |
| NTP Amplification | Spoofed NTP monlist requests | Shield Standard/Advanced (automatic) |
| SSDP Reflection | Spoofed SSDP requests to IoT devices | Shield Standard/Advanced (automatic) |
| ICMP Flood | High-volume ICMP echo requests | Security Groups (block ICMP) + Shield |
| IP Fragmentation | Fragmented packets exhausting reassembly buffers | Shield Advanced (automatic) |

**AWS defense posture:** Shield Standard automatically mitigates most Layer 3/4 attacks for resources behind CloudFront, Route 53, and Global Accelerator. Shield Advanced provides enhanced detection, real-time metrics, and SRT access.

### Layer 7 (Application-Layer Attacks)

| Attack Type | Description | Primary AWS Mitigation |
|---|---|---|
| HTTP Flood | High-volume legitimate-looking HTTP requests | WAF rate-based rules + Bot Control |
| Slowloris | Slow, incomplete HTTP connections exhausting server threads | ALB connection timeouts + WAF |
| RUDY (R-U-Dead-Yet) | Slow POST requests with large Content-Length | ALB request timeout + WAF |
| Cache-Busting | Requests with unique query strings bypassing CDN cache | CloudFront + WAF custom rules |
| API Abuse | Targeting expensive API endpoints (search, reports) | WAF rate-based rules + API Gateway throttling |
| WordPress XML-RPC | Amplification via WordPress pingback | WAF managed rules (WordPress protection) |
| Login Brute Force | High-volume authentication attempts | WAF rate-based rules + CAPTCHA |

**AWS defense posture:** Layer 7 attacks require WAF rules (rate-based, Bot Control, custom rules) and application-level controls (API Gateway throttling, caching strategies). Shield Advanced automatic application-layer mitigation can create WAF rules based on observed attack patterns.

---

## Appendix E — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- [AWS Security Incident Response Service Documentation](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Well-Architected Framework — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [AWS Best Practices for DDoS Resiliency (Whitepaper)](https://docs.aws.amazon.com/whitepapers/latest/aws-best-practices-ddos-resiliency/aws-best-practices-ddos-resiliency.html)
- [AWS Shield Documentation](https://docs.aws.amazon.com/waf/latest/developerguide/shield-chapter.html)
- [AWS Shield Advanced — Responding to DDoS Events](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-responding.html)
- [AWS Shield Response Team (SRT) Engagement](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-srt.html)
- [AWS WAF Documentation](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html)
- [AWS WAF Rate-Based Rules](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html)
- [AWS WAF Bot Control](https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control.html)
- [Shield Advanced Cost Protection](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-cost-protection.html)
- [Shield Advanced Proactive Engagement](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-srt-proactive-engagement.html)
- [CloudFront Security Best Practices](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/security-best-practices.html)
- [Route 53 DDoS Resilience](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/disaster-recovery-resiliency.html)
- [AWS Global Accelerator DDoS Protection](https://docs.aws.amazon.com/global-accelerator/latest/dg/introduction-how-it-works.html)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [VPC Flow Logs Querying with Athena](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-athena.html)
- [AWS Well-Architected Framework — Reliability Pillar: DDoS Mitigation](https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/plan-for-disaster-recovery-dr.html)
- [AWS CIRT Incident Response Workshops](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-release-of-five-publicly-available-workshops/)
- [NIS2 Directive — Incident Reporting Requirements](https://digital-strategy.ec.europa.eu/en/policies/nis2-directive)
- [DORA — Digital Operational Resilience Act](https://www.digital-operational-resilience-act.com/)
- [Threat Technique Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/)

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2024-03-15 | IR Team | Initial draft |
| 2.0 | 2026-05-28 | IR Team | Major refresh: Added Shield Advanced automatic app-layer mitigation, WAF Bot Control, Global Accelerator, EventBridge automation hooks, NIS2/DORA regulatory guidance, expanded Layer 7 containment procedures, updated Athena queries for WAF v2 log format |
| 2.1 | 2026-06-18 | IR Team | Aligned to playbook template v2: Added context paragraphs, Well-Architected references (SEC10-BP01/04/05/06), moved Athena queries to companion SQL file, trimmed CLI bulk in containment/eradication (kept key examples), added "When to Engage" column, expanded severity to P1–P3 AWS engagement guidance, fixed spelling (characterize/randomized/prioritize), updated terminology (threat actor), added forward references for upcoming playbooks |
