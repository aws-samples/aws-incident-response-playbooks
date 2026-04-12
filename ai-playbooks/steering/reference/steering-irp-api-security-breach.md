---
inclusion: manual
description: |
  Incident response playbook for API security breaches on AWS (OWASP API Top 10).
  Covers broken authentication, broken object-level authorization (BOLA), broken function-level authorization (BFLA),
  injection attacks, excessive data exposure, lack of rate limiting, SSRF, mass assignment, and security misconfiguration
  targeting APIs hosted on Amazon API Gateway, Application Load Balancer, Lambda, ECS, and EKS.
  - Invoke with "steering-irp-api-security-breach.md" when responding to API security incidents.
  - Invoke with "steering-irp-credential-compromise.md" when responding to compromised credentials.
  - Invoke with "steering-irp-data-access.md" when responding to unintended access to Amazon S3 buckets.
  - Invoke with "steering-irp-ransomware.md" when responding to ransomware incidents.
---

# Playbook: API Security Breach (OWASP API Top 10)

## Incident Type
API Security Breach — When an AWS-hosted API (API Gateway, ALB, Lambda, ECS/EKS backends) is suspected of being exploited through OWASP API Top 10 attack vectors. This includes broken authentication, broken object-level authorization (BOLA), broken function-level authorization (BFLA), injection (SQLi, NoSQLi, command injection), excessive data exposure, lack of rate limiting / resource exhaustion, Server-Side Request Forgery (SSRF), mass assignment, and security misconfiguration. The operator may observe anomalous API traffic patterns, unexpected 4xx/5xx spikes, WAF rule triggers, data leakage reports, or GuardDuty findings on backend compute.

## Quick Reference

| Phase | Key Action | Verification |
|-------|------------|--------------|
| Evidence | Identify affected API(s), attack vector, attacker IPs, timeline | API ID, attack type, source IPs, compromise window documented |
| Contain | Block attacker IPs via WAF/NACL, throttle API, disable compromised auth | WAF logs show blocked requests, no new malicious traffic for 30+ min |
| Eradicate | Remove attacker persistence, patch vulnerable endpoints, harden WAF rules | No unauthorized API access, vulnerability patched |
| Recover | Restore modified data, re-enable throttled services, verify API functionality | Applications functioning normally, monitoring clean |
| Post-Incident | Document lessons learned, update WAF rules and API security posture | Report filed, playbook updated |

---

## Part 1: Acquire, Preserve, Document Evidence

### 1.1 Identify the Alert Source

Common sources for API security breach alerts:
- **AWS WAF logs** (rule match events — SQLi, XSS, rate-based rule triggers)
- **API Gateway CloudWatch metrics** (spike in 4xx/5xx errors, latency anomalies, `Count` metric surge)
- **API Gateway access logs** (unusual request patterns, unexpected endpoints, large response sizes)
- **GuardDuty findings** on backend compute (e.g., `Backdoor:Lambda/C&CActivity.B`, `UnauthorizedAccess:Lambda/MaliciousIPCaller.Custom`, `Execution:Runtime/ReverseShell`, `AttackSequence:ECS/CompromisedCluster`)
- **CloudWatch alarms** (error rate thresholds, latency thresholds, concurrent execution spikes)
- **Security Hub alerts** (API Gateway or WAF-related controls)
- **Amazon Macie** (if API responses are logged and contain sensitive data)
- **Billing anomalies** (unexpected Lambda invocation costs, data transfer spikes)
- **External notification** (security researcher, customer report, bug bounty submission)

### 1.2 Identify the Affected API(s)

```bash
# List all API Gateway REST APIs
aws apigateway get-rest-apis

# List all API Gateway HTTP APIs
aws apigatewayv2 get-apis

# Get details of a specific REST API
aws apigateway get-rest-api --rest-api-id <api-id>

# List stages for the API
aws apigateway get-stages --rest-api-id <api-id>

# List resources (endpoints) for the API
aws apigateway get-resources --rest-api-id <api-id>
```

# MCP batch opportunity: List REST APIs and HTTP APIs in parallel

**If the alert references an ALB-fronted API:**
```bash
# List ALBs
aws elbv2 describe-load-balancers --query 'LoadBalancers[?Type==`application`]'

# Get ALB access logs configuration
aws elbv2 describe-load-balancer-attributes --load-balancer-arn <alb-arn> \
  --query 'Attributes[?Key==`access_logs.s3.enabled`]'
```

### 1.3 Determine the Attack Vector (OWASP API Top 10 Classification)

Analyze available logs to classify the attack. Check WAF logs, API Gateway access logs, and application logs for these patterns:

**API1 — Broken Object-Level Authorization (BOLA):**
- Sequential or enumerated IDs in request paths (e.g., `/users/1`, `/users/2`, `/users/3`)
- Single authenticated user accessing resources belonging to other users
- High volume of requests to parameterized endpoints with varying IDs

**API2 — Broken Authentication:**
- Brute-force login attempts (high volume of 401 responses)
- Credential stuffing patterns (many different usernames, same endpoint)
- Token reuse or expired token replay
- Missing or weak authentication on sensitive endpoints

**API3 — Broken Object Property Level Authorization:**
- Requests returning more data fields than expected
- Mass assignment attempts (PUT/PATCH with unexpected fields)
- API responses containing internal/sensitive fields (e.g., `isAdmin`, `password_hash`)

**API4 — Unrestricted Resource Consumption:**
- Abnormal request volume from single IP or API key
- Rate limit exhaustion (429 responses followed by continued attempts)
- Large payload requests causing backend resource exhaustion
- GraphQL complexity attacks (deeply nested queries)

**API5 — Broken Function-Level Authorization (BFLA):**
- Non-admin users calling admin endpoints
- HTTP method tampering (GET → PUT/DELETE on read-only endpoints)
- Access to internal/management API paths from external sources

**API6 — Unrestricted Access to Sensitive Business Flows:**
- Automated abuse of business-critical flows (e.g., mass account creation, inventory hoarding)
- Bot-like request patterns (consistent timing, missing browser fingerprints)

**API7 — Server-Side Request Forgery (SSRF):**
- Requests containing internal URLs or metadata endpoints (`169.254.169.254`)
- Unexpected outbound connections from backend compute
- GuardDuty findings: `UnauthorizedAccess:Runtime/MetadataDNSRebind`

**API8 — Security Misconfiguration:**
- Verbose error messages exposing stack traces or internal paths
- Default credentials or API keys in use
- CORS misconfiguration allowing unauthorized origins
- Missing security headers

**API9 — Improper Inventory Management:**
- Traffic to deprecated or undocumented API versions
- Access to debug/test endpoints in production
- Shadow APIs receiving traffic

**API10 — Unsafe Consumption of APIs:**
- Backend making unvalidated calls to third-party APIs
- Data injection through upstream API responses

### 1.4 Collect WAF Logs and Metrics

```bash
# Get WAF Web ACL associated with the API
aws wafv2 list-web-acls --scope REGIONAL

# Get sampled requests for a specific WAF rule
aws wafv2 get-sampled-requests \
  --web-acl-arn <web-acl-arn> \
  --rule-metric-name <rule-metric-name> \
  --scope REGIONAL \
  --time-window StartTime=<start-timestamp>,EndTime=<end-timestamp> \
  --max-items 100

# Get WAF logging configuration
aws wafv2 get-logging-configuration --resource-arn <web-acl-arn>
```

**If WAF logs are in S3 or CloudWatch Logs, query them for attack patterns:**
```bash
# If WAF logs are in CloudWatch Logs Insights
aws logs start-query \
  --log-group-name <waf-log-group> \
  --start-time <epoch-start> \
  --end-time <epoch-end> \
  --query-string 'fields @timestamp, httpRequest.clientIp, httpRequest.uri, action
    | filter action = "BLOCK"
    | stats count(*) as blocked_count by httpRequest.clientIp
    | sort blocked_count desc
    | limit 20'
```

### 1.5 Collect API Gateway Access Logs

```bash
# Check if access logging is enabled on the stage
aws apigateway get-stage --rest-api-id <api-id> --stage-name <stage-name> \
  --query 'accessLogSettings'

# Query API Gateway access logs in CloudWatch Logs Insights
aws logs start-query \
  --log-group-name <api-access-log-group> \
  --start-time <epoch-start> \
  --end-time <epoch-end> \
  --query-string 'fields @timestamp, ip, httpMethod, resourcePath, status, responseLength
    | filter status >= 400
    | stats count(*) as error_count by ip, resourcePath, status
    | sort error_count desc
    | limit 50'
```

# MCP batch opportunity: Query WAF logs and API Gateway access logs in parallel

### 1.6 Collect CloudTrail Events for API Infrastructure Changes

```bash
# Check for recent API Gateway configuration changes
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=apigateway.amazonaws.com \
  --start-time <start-timestamp> \
  --max-results 50

# Check for WAF configuration changes
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=wafv2.amazonaws.com \
  --start-time <start-timestamp> \
  --max-results 50

# Check for Lambda function changes (if Lambda backend)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=lambda.amazonaws.com \
  --start-time <start-timestamp> \
  --max-results 50
```

# MCP batch opportunity: Query CloudTrail for apigateway, wafv2, and lambda event sources in parallel

Look for these suspicious management events:
- `UpdateRestApi`, `UpdateStage`, `CreateDeployment` (API config changes)
- `UpdateWebACL`, `DeleteWebACL`, `DeleteRule` (WAF weakening)
- `UpdateFunctionCode`, `UpdateFunctionConfiguration` (Lambda tampering)
- `CreateAuthorizer`, `UpdateAuthorizer`, `DeleteAuthorizer` (auth bypass)

### 1.7 Check Backend Compute for Compromise

**For Lambda backends:**
```bash
# List recent Lambda invocations with errors
aws logs start-query \
  --log-group-name /aws/lambda/<function-name> \
  --start-time <epoch-start> \
  --end-time <epoch-end> \
  --query-string 'fields @timestamp, @message
    | filter @message like /(?i)(error|exception|timeout|injection|unauthorized)/
    | sort @timestamp desc
    | limit 50'

# Check Lambda function configuration for tampering
aws lambda get-function-configuration --function-name <function-name>

# Check for environment variable changes (potential secrets exfiltration)
aws lambda get-function-configuration --function-name <function-name> \
  --query 'Environment.Variables'
```

**For ECS/EKS backends:**
```bash
# List ECS services in the cluster
aws ecs list-services --cluster <cluster-name>

# Describe tasks for anomalies
aws ecs describe-tasks --cluster <cluster-name> --tasks <task-id>

# Check for GuardDuty ECS findings
aws guardduty list-findings --detector-id <detector-id> \
  --finding-criteria '{"Criterion":{"resource.resourceType":{"Eq":["ECSCluster"]}}}'
```

### 1.8 Establish Timeline

Document the following timestamps:
- **First malicious request:** Earliest attack indicator in WAF/access logs
- **Attack escalation:** When attack pattern changed (e.g., recon → exploitation)
- **Data exposure window:** Period during which data may have been exfiltrated
- **Detection time:** When the alert was generated
- **Response start:** When the operator began investigating

### 1.9 Document and Communicate

- [ ] Create/update incident ticket with: API ID(s), attack vector (OWASP classification), source IPs, timeline, affected endpoints
- [ ] Identify stakeholders from CMDB (API owners, backend service owners)
- [ ] Open war room bridge
- [ ] Notify: Security team, API/application owners, Legal (if data exposure suspected)
- [ ] If customer data was exposed: Notify privacy/compliance team immediately

---

## Part 2: Contain the Incident

**Goal:** Stop active exploitation immediately. Block attacker access, throttle abused endpoints, and disable compromised authentication mechanisms.

### 2.1 Block Attacker IPs via WAF

```bash
# Create an IP set with attacker IPs
aws wafv2 create-ip-set \
  --name "IR-Blocked-IPs-<incident-id>" \
  --scope REGIONAL \
  --ip-address-version IPV4 \
  --addresses <attacker-ip-1>/32 <attacker-ip-2>/32

# Get current Web ACL for update
aws wafv2 get-web-acl --name <web-acl-name> --scope REGIONAL --id <web-acl-id>

# Update Web ACL to add a block rule for the IP set (use the lock-token from get-web-acl)
# Add a rule with priority 0 (highest) that blocks the IP set
aws wafv2 update-web-acl \
  --name <web-acl-name> \
  --scope REGIONAL \
  --id <web-acl-id> \
  --lock-token <lock-token> \
  --default-action '{"Allow":{}}' \
  --rules '[{
    "Name": "IR-Block-Attacker-IPs",
    "Priority": 0,
    "Statement": {
      "IPSetReferenceStatement": {
        "ARN": "<ip-set-arn>"
      }
    },
    "Action": {"Block": {}},
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "IR-Block-Attacker-IPs"
    }
  }]'
```

⚠️ **Warning:** Ensure the `--rules` parameter includes ALL existing rules plus the new block rule. Omitting existing rules will remove them.

**If no WAF is associated with the API:**
```bash
# Create a Web ACL with the block rule and associate it
aws wafv2 create-web-acl \
  --name "IR-Emergency-WAF-<incident-id>" \
  --scope REGIONAL \
  --default-action '{"Allow":{}}' \
  --rules '[{
    "Name": "IR-Block-Attacker-IPs",
    "Priority": 0,
    "Statement": {
      "IPSetReferenceStatement": {"ARN": "<ip-set-arn>"}
    },
    "Action": {"Block": {}},
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "IR-Block-Attacker-IPs"
    }
  }]' \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=IR-Emergency-WAF

# Associate with API Gateway stage
aws wafv2 associate-web-acl \
  --web-acl-arn <web-acl-arn> \
  --resource-arn arn:aws:apigateway:<region>::/restapis/<api-id>/stages/<stage-name>
```

### 2.2 Apply Emergency Rate Limiting

```bash
# Add a rate-based rule to the Web ACL (e.g., 100 requests per 5 minutes per IP)
# Include this in the update-web-acl call alongside the IP block rule
```

**For API Gateway native throttling:**
```bash
# Set aggressive throttling on the stage
aws apigateway update-stage --rest-api-id <api-id> --stage-name <stage-name> \
  --patch-operations op=replace,path=/throttling/rateLimit,value=50 \
  op=replace,path=/throttling/burstLimit,value=25

# Throttle specific vulnerable endpoints more aggressively
aws apigateway update-method --rest-api-id <api-id> \
  --resource-id <resource-id> --http-method <method> \
  --patch-operations op=replace,path=/throttling/rateLimit,value=10 \
  op=replace,path=/throttling/burstLimit,value=5
```

⚠️ **Warning:** Aggressive throttling affects legitimate users. Coordinate with API owners and set limits based on normal traffic baselines.

### 2.3 Disable Compromised Authentication

**If API keys are compromised:**
```bash
# List API keys
aws apigateway get-api-keys --include-values

# Disable the compromised API key
aws apigateway update-api-key --api-key <api-key-id> \
  --patch-operations op=replace,path=/enabled,value=false
```

**If Cognito user pool tokens are compromised:**
```bash
# Disable the compromised user
aws cognito-idp admin-disable-user \
  --user-pool-id <user-pool-id> \
  --username <username>

# Force global sign-out (invalidates all tokens)
aws cognito-idp admin-user-global-sign-out \
  --user-pool-id <user-pool-id> \
  --username <username>
```

**If Lambda authorizer is compromised:**
```bash
# Check the authorizer configuration
aws apigateway get-authorizers --rest-api-id <api-id>

# If the authorizer Lambda was tampered with, update it to a known-good version
aws lambda update-function-code --function-name <authorizer-function> \
  --s3-bucket <deployment-bucket> --s3-key <known-good-package>
```

### 2.4 Network-Level Containment (if WAF is insufficient)

```bash
# If the API backend is in a VPC, add NACL deny rules for attacker IPs
aws ec2 create-network-acl-entry \
  --network-acl-id <nacl-id> \
  --rule-number 50 \
  --protocol -1 \
  --rule-action deny \
  --cidr-block <attacker-ip>/32 \
  --ingress
```

### 2.5 Verify Containment

```bash
# Monitor WAF logs for continued attack attempts (should show BLOCK actions)
aws wafv2 get-sampled-requests \
  --web-acl-arn <web-acl-arn> \
  --rule-metric-name "IR-Block-Attacker-IPs" \
  --scope REGIONAL \
  --time-window StartTime=$(date -u -v-30M +%Y-%m-%dT%H:%M:%SZ),EndTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --max-items 20

# Check API Gateway metrics for traffic normalization
aws cloudwatch get-metric-statistics \
  --namespace AWS/ApiGateway \
  --metric-name 4XXError \
  --dimensions Name=ApiName,Value=<api-name> \
  --start-time $(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 300 \
  --statistics Sum

# Verify no new malicious requests are succeeding in access logs
aws logs start-query \
  --log-group-name <api-access-log-group> \
  --start-time $(date -u -v-30M +%s) \
  --end-time $(date -u +%s) \
  --query-string 'fields @timestamp, ip, status
    | filter ip in [<attacker-ips>]
    | sort @timestamp desc
    | limit 20'
```

If new successful requests from attacker IPs appear, containment failed — investigate alternate access paths (different IPs, different API keys, direct backend access).

---

## Part 3: Eradicate the Incident

**Goal:** Remove attacker persistence, patch exploited vulnerabilities, and harden API security configuration.

### 3.1 Patch Vulnerable API Endpoints

Based on the attack vector identified in Part 1:

**For injection vulnerabilities (API1, API8):**
- Review and fix input validation in backend code
- Add WAF managed rule groups:
```bash
# Add AWS Managed Rules for SQL injection and known bad inputs
# Include AWSManagedRulesSQLiRuleSet and AWSManagedRulesKnownBadInputsRuleSet
# in the Web ACL update
aws wafv2 update-web-acl \
  --name <web-acl-name> \
  --scope REGIONAL \
  --id <web-acl-id> \
  --lock-token <lock-token> \
  --default-action '{"Allow":{}}' \
  --rules '<include-existing-rules-plus-managed-rule-groups>'
```

**For authorization vulnerabilities (BOLA/BFLA — API1, API5):**
- Review API Gateway resource policies and authorizer logic
- Verify object-level authorization checks in backend code
- Add request validation:
```bash
# Create a request validator
aws apigateway create-request-validator --rest-api-id <api-id> \
  --name "IR-RequestValidator" \
  --validate-request-body true \
  --validate-request-parameters true
```

**For SSRF (API7):**
```bash
# Enforce IMDSv2 on EC2 instances backing the API
aws ec2 modify-instance-metadata-options \
  --instance-id <instance-id> \
  --http-tokens required \
  --http-endpoint enabled

# Review Lambda function network configuration
aws lambda get-function-configuration --function-name <function-name> \
  --query 'VpcConfig'
```

### 3.2 Remove Attacker Persistence

```bash
# Check for unauthorized API keys created during the attack
aws apigateway get-api-keys --include-values \
  --query 'items[?createdDate>=`<compromise-timestamp>`]'

# Check for unauthorized Cognito users
aws cognito-idp list-users --user-pool-id <user-pool-id> \
  --filter 'status = "Enabled"' \
  --query 'Users[?UserCreateDate>=`<compromise-timestamp>`]'

# Check for modified Lambda functions
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionCode \
  --start-time <compromise-timestamp> \
  --max-results 20

# Check for new or modified API Gateway authorizers
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAuthorizer \
  --start-time <compromise-timestamp> \
  --max-results 20
```

# MCP batch opportunity: Query for unauthorized API keys, Cognito users, and CloudTrail events in parallel

**Remove any attacker-created resources:**
```bash
# Delete unauthorized API keys
aws apigateway delete-api-key --api-key <unauthorized-key-id>

# Delete unauthorized Cognito users
aws cognito-idp admin-delete-user \
  --user-pool-id <user-pool-id> \
  --username <unauthorized-username>

# Revert tampered Lambda functions to known-good versions
aws lambda update-function-code --function-name <function-name> \
  --s3-bucket <deployment-bucket> --s3-key <known-good-package>
```

### 3.3 Harden WAF Configuration

```bash
# Enable AWS Managed Rule Groups for comprehensive API protection
# Key rule groups for API security:
# - AWSManagedRulesCommonRuleSet (general protection)
# - AWSManagedRulesSQLiRuleSet (SQL injection)
# - AWSManagedRulesKnownBadInputsRuleSet (known bad inputs including Log4j)
# - AWSManagedRulesBotControlRuleSet (bot management)
# - AWSManagedRulesATPRuleSet (account takeover prevention)

# List available managed rule groups
aws wafv2 list-available-managed-rule-groups --scope REGIONAL
```

### 3.4 Harden API Gateway Configuration

```bash
# Enable CloudWatch execution logging (if not already enabled)
aws apigateway update-stage --rest-api-id <api-id> --stage-name <stage-name> \
  --patch-operations op=replace,path/logging/loglevel,value=INFO

# Enable access logging (if not already enabled)
aws apigateway update-stage --rest-api-id <api-id> --stage-name <stage-name> \
  --patch-operations op=replace,path=/accessLogSettings/destinationArn,value=<log-group-arn>

# Enable X-Ray tracing for request tracing
aws apigateway update-stage --rest-api-id <api-id> --stage-name <stage-name> \
  --patch-operations op=replace,path=/tracingEnabled,value=true

# Ensure mutual TLS is configured (if applicable)
aws apigateway get-rest-api --rest-api-id <api-id> \
  --query 'mutualTlsAuthentication'
```

Checklist:
- [ ] WAF associated with all API stages with appropriate managed rule groups
- [ ] Rate-based rules configured with appropriate thresholds
- [ ] API Gateway access logging enabled
- [ ] API Gateway execution logging enabled
- [ ] Request validation enabled on all endpoints
- [ ] Authorizers properly configured and tested
- [ ] CORS configuration restricted to authorized origins only
- [ ] API keys rotated if any were compromised
- [ ] Backend Lambda/ECS/EKS patched and verified

If eradication reveals a different attack vector (e.g., credential compromise, data exfiltration beyond the API layer), loop back to Part 1 and invoke the corresponding additional playbook.

---

## Part 4: Recover from the Incident

**Goal:** Restore normal API operations, verify data integrity, and confirm security controls are effective.

### 4.1 Restore Normal Traffic Levels

```bash
# Revert emergency throttling to normal levels
aws apigateway update-stage --rest-api-id <api-id> --stage-name <stage-name> \
  --patch-operations op=replace,path=/throttling/rateLimit,value=<normal-rate> \
  op=replace,path=/throttling/burstLimit,value=<normal-burst>
```

⚠️ **Warning:** Only restore normal throttling after confirming containment is effective and vulnerabilities are patched.

### 4.2 Restore Compromised Data

If the attacker modified data through the API:

```bash
# Check DynamoDB for point-in-time recovery
aws dynamodb describe-continuous-backups --table-name <table-name>

# Restore DynamoDB table to pre-attack state
aws dynamodb restore-table-to-point-in-time \
  --source-table-name <table-name> \
  --target-table-name <table-name>-restored \
  --restore-date-time <pre-attack-timestamp>

# If RDS backend, check for snapshots
aws rds describe-db-snapshots --db-instance-identifier <db-instance-id>

# Restore from snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier <db-instance-id>-restored \
  --db-snapshot-identifier <snapshot-id>
```

**If S3 data was accessed/modified through the API:**
```bash
# Check S3 versioning for object restoration
aws s3api list-object-versions --bucket <bucket-name> --prefix <key-prefix>

# Restore previous version
aws s3api copy-object \
  --bucket <bucket-name> \
  --key <object-key> \
  --copy-source <bucket-name>/<object-key>?versionId=<version-id>
```

### 4.3 Re-issue Credentials

```bash
# Create new API keys for legitimate users whose keys were disabled
aws apigateway create-api-key --name <key-name> --enabled true

# Associate new key with usage plan
aws apigateway create-usage-plan-key \
  --usage-plan-id <usage-plan-id> \
  --key-id <new-api-key-id> \
  --key-type API_KEY

# Re-enable Cognito users that were disabled during containment
aws cognito-idp admin-enable-user \
  --user-pool-id <user-pool-id> \
  --username <username>
```

### 4.4 Verify Recovery

- [ ] API endpoints returning expected responses (test with known-good requests)
- [ ] Error rates returned to pre-incident baseline
- [ ] Latency metrics within normal range
- [ ] WAF blocking only malicious traffic (no false positives on legitimate users)
- [ ] Backend data integrity confirmed
- [ ] Legitimate users and API consumers can authenticate and access resources
- [ ] Monitoring dashboards show normal patterns

```bash
# Verify API health via CloudWatch
aws cloudwatch get-metric-statistics \
  --namespace AWS/ApiGateway \
  --metric-name Count \
  --dimensions Name=ApiName,Value=<api-name> \
  --start-time $(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 300 \
  --statistics Sum
```

If suspicious activity reoccurs, return to Part 1 and reassess the attack vector.

---

## Part 5: Post-Incident Activity

### 5.1 Document Lessons Learned

Create post-incident report covering:
- **Timeline:** When did each phase occur (first malicious request → detection → containment → resolution)?
- **Root cause:** Which OWASP API Top 10 vulnerability was exploited? How did it exist?
- **Impact:** What data was accessed/modified? How many users/customers affected?
- **Response effectiveness:** What worked? What didn't? How long was the exposure window?
- **Recommendations:** Code fixes, WAF rule improvements, monitoring enhancements

### 5.2 Retrospective Questions

- Was WAF configured and logging before the incident? If not, why?
- Were API Gateway access logs enabled? Could we have detected this sooner?
- Did the API have proper authentication and authorization on all endpoints?
- Was input validation implemented at both the API Gateway and backend levels?
- Are there other APIs with similar vulnerabilities that need proactive remediation?
- Would API schema validation (OpenAPI spec enforcement) have prevented this?

### 5.3 Update Defenses

Based on findings:
- [ ] Deploy WAF with managed rule groups on all API stages
- [ ] Enable API Gateway access logging and execution logging on all stages
- [ ] Implement request validation using API Gateway models
- [ ] Review and enforce least-privilege API authorization
- [ ] Add rate limiting appropriate to each endpoint's expected traffic
- [ ] Enable GuardDuty Lambda Protection and/or Runtime Monitoring for backend compute
- [ ] Implement API schema validation (OpenAPI specification enforcement)
- [ ] Set up CloudWatch alarms for API error rate and latency anomalies
- [ ] Consider AWS Shield Advanced for DDoS protection on API endpoints
- [ ] Schedule regular API security assessments (penetration testing)
- [ ] Propose updates to this playbook and related steering files based on lessons learned — present changes to the operator for review and approval before modifying any steering files

### 5.4 Regulatory Notifications

If required by your jurisdiction:
- [ ] Notify relevant authorities within required timeframe
- [ ] If customer PII was exposed via the API, follow data breach notification requirements
- [ ] Document notification for compliance records

---

## References

- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [Amazon API Gateway Security Best Practices](https://docs.aws.amazon.com/apigateway/latest/developerguide/security-best-practices.html)
- [Protecting REST APIs with AWS WAF](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html)
- [AWS WAF Managed Rule Groups](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html)
- [API Gateway CloudWatch Logging](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html)
- [API Gateway Throttling](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html)
- [GuardDuty Lambda Protection](https://docs.aws.amazon.com/guardduty/latest/ug/lambda-protection.html)
- [GuardDuty Runtime Monitoring](https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [NIST SP 800-61 R3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
