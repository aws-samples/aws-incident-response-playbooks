# AI IRP: API Security Breach (OWASP API Top 10)

An AWS-hosted API (API Gateway, ALB, Lambda, ECS/EKS backend) is being actively exploited. Covers BOLA, broken auth, injection, SSRF, rate limiting abuse, and security misconfiguration. Key principle: WAF containment first, then investigate the specific vulnerability.

## Critical Rule

```
╔══════════════════════════════════════════════════════════════╗
║  BLOCK ATTACKER IPs VIA WAF IMMEDIATELY.                    ║
║  Then investigate the specific vulnerability.               ║
║  Do NOT patch the vulnerability before containing           ║
║  the active exploitation — stop the bleeding first.         ║
╚══════════════════════════════════════════════════════════════╝
```

## Priority Assessment

| Signal | Priority |
|--------|----------|
| Active data exfiltration via API (confirmed) | P1 |
| Injection attack with backend command execution confirmed | P1 |
| BOLA/BFLA with confirmed access to other users' data | P1 |
| WAF rule triggers + elevated 4xx errors from single source | P2 |
| Authentication bypass suspected, scope unclear | P2 |
| Rate limit exceeded, no confirmed data impact | P3 |
| Security misconfiguration found in review (no active exploitation) | P4 |

## Step 1: Identify the Attack

Determine which OWASP API Top 10 category you're dealing with.

```bash
# Check WAF logs for blocked/counted requests
aws wafv2 get-sampled-requests \
  --web-acl-arn WEB_ACL_ARN \
  --rule-metric-name TRIGGERED_RULE_NAME \
  --scope REGIONAL \
  --time-window StartTime=START_TIMESTAMP,EndTime=END_TIMESTAMP \
  --max-items 50

# Check API Gateway access logs for error patterns
aws logs start-query \
  --log-group-name API_ACCESS_LOG_GROUP \
  --start-time START_EPOCH \
  --end-time END_EPOCH \
  --query-string 'fields @timestamp, ip, httpMethod, resourcePath, status, responseLength
    | filter status >= 400
    | stats count(*) as error_count by ip, resourcePath, status
    | sort error_count desc
    | limit 30'

# Get query results (wait ~5 seconds after start-query)
aws logs get-query-results --query-id QUERY_ID
```

**Decision: Classify the attack**

| Pattern | OWASP Category | Key Indicator |
|---------|----------------|---------------|
| Sequential/enumerated IDs from single auth'd user | API1 — BOLA | `/users/1`, `/users/2`, `/users/3`... |
| High-volume 401s then successful auth | API2 — Broken Auth | Brute force / credential stuffing |
| Responses returning unexpected fields | API3 — Property Auth | `isAdmin`, `password_hash` in response |
| Extreme request volume from single source | API4 — Resource Consumption | Rate limit exhaustion |
| Non-admin calling admin endpoints | API5 — BFLA | HTTP method tampering, admin path access |
| Requests with `169.254.169.254` or internal URLs | API7 — SSRF | Metadata service access attempt |
| Verbose error messages / stack traces returned | API8 — Misconfiguration | Debug mode in production |

## Step 2: Contain — Block Attacker IPs via WAF

> ⚠️ **Requires user confirmation before executing.**

```bash
# Create IP set with attacker IPs
aws wafv2 create-ip-set \
  --name "IR-Blocked-IPs-INCIDENT_ID" \
  --scope REGIONAL \
  --ip-address-version IPV4 \
  --addresses "ATTACKER_IP_1/32" "ATTACKER_IP_2/32"

# Note: You must then update the Web ACL to include a block rule
# referencing this IP set. Get the current Web ACL first:
aws wafv2 get-web-acl --name WEB_ACL_NAME --scope REGIONAL --id WEB_ACL_ID
```

**Present to user:**
> "I recommend blocking IPs [ATTACKER_IPS] via WAF. This will immediately deny all requests from these sources. It will NOT affect other users. The existing Web ACL rules remain intact. Shall I proceed?"

**If no WAF exists on the API:**

```bash
# Apply emergency throttling directly on API Gateway stage
aws apigateway update-stage --rest-api-id API_ID --stage-name STAGE_NAME \
  --patch-operations op=replace,path=/throttling/rateLimit,value=50 \
  op=replace,path=/throttling/burstLimit,value=25
```

> ⚠️ Throttling affects ALL users. Only use if WAF is not available and attack is active.

## Step 3: Contain — Disable Compromised Authentication

> ⚠️ **Requires user confirmation before executing.**

**If API keys compromised:**
```bash
aws apigateway update-api-key --api-key API_KEY_ID \
  --patch-operations op=replace,path=/enabled,value=false
```

**If Cognito tokens compromised:**
```bash
# Disable compromised user and force global sign-out
aws cognito-idp admin-disable-user \
  --user-pool-id USER_POOL_ID \
  --username COMPROMISED_USERNAME

aws cognito-idp admin-user-global-sign-out \
  --user-pool-id USER_POOL_ID \
  --username COMPROMISED_USERNAME
```

**Present to user:**
> "I recommend disabling [credential type] for [identity]. Active sessions will be invalidated. Applications using this credential will stop working. Shall I proceed?"

## Step 4: Investigate — Scope the Damage

Read-only — execute freely.

```bash
# Check for API infrastructure changes during the attack
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=apigateway.amazonaws.com \
  --start-time START_TIMESTAMP \
  --max-results 50

# Check for WAF tampering (attacker may have weakened rules)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=wafv2.amazonaws.com \
  --start-time START_TIMESTAMP \
  --max-results 20

# Check for Lambda function code changes (backend tampering)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionCode \
  --start-time START_TIMESTAMP \
  --max-results 20
```

**Key Athena query — attacker request patterns:**

```sql
SELECT sourceIPAddress, COUNT(*) AS request_count,
       COUNT(CASE WHEN errorCode IS NULL THEN 1 END) AS successful,
       COUNT(CASE WHEN errorCode IS NOT NULL THEN 1 END) AS failed,
       ARRAY_AGG(DISTINCT userAgent) AS user_agents
FROM cloudtrail_logs
WHERE eventSource = 'apigateway.amazonaws.com'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
  AND sourceIPAddress IN ('ATTACKER_IP_1', 'ATTACKER_IP_2')
GROUP BY sourceIPAddress
ORDER BY request_count DESC;
```

**Check for attacker persistence:**
- [ ] Unauthorized API keys created during attack window?
- [ ] Unauthorized Cognito users created?
- [ ] Lambda authorizer function modified?
- [ ] New API Gateway authorizers created?
- [ ] WAF rules deleted or weakened?

## Step 5: Eradicate — Patch and Harden

> ⚠️ **Requires user confirmation before executing.**

```bash
# Remove any unauthorized API keys created by attacker
aws apigateway delete-api-key --api-key UNAUTHORIZED_KEY_ID

# Remove unauthorized Cognito users
aws cognito-idp admin-delete-user \
  --user-pool-id USER_POOL_ID \
  --username UNAUTHORIZED_USERNAME

# Revert tampered Lambda functions to known-good version
aws lambda update-function-code --function-name FUNCTION_NAME \
  --s3-bucket DEPLOYMENT_BUCKET --s3-key KNOWN_GOOD_PACKAGE

# Add managed WAF rule groups for comprehensive protection
# (AWSManagedRulesCommonRuleSet, AWSManagedRulesSQLiRuleSet,
#  AWSManagedRulesKnownBadInputsRuleSet)
aws wafv2 list-available-managed-rule-groups --scope REGIONAL
```

**Hardening by OWASP category:**

| Category | Fix |
|----------|-----|
| BOLA (API1) | Add object-level authorization checks in backend code |
| Broken Auth (API2) | Enforce rate limiting on auth endpoints, add account lockout |
| SSRF (API7) | Enforce IMDSv2, restrict outbound network access |
| Misconfiguration (API8) | Disable verbose errors, enforce HTTPS, restrict CORS |
| Rate Limiting (API4) | Configure per-endpoint throttling in API Gateway |

## Step 6: Recover and Validate

> ⚠️ **Requires user confirmation before executing.**

```bash
# Restore normal throttling (only after vulnerabilities patched)
aws apigateway update-stage --rest-api-id API_ID --stage-name STAGE_NAME \
  --patch-operations op=replace,path=/throttling/rateLimit,value=NORMAL_RATE \
  op=replace,path=/throttling/burstLimit,value=NORMAL_BURST

# Re-enable legitimate API keys/users that were disabled during containment
aws apigateway update-api-key --api-key LEGITIMATE_KEY_ID \
  --patch-operations op=replace,path=/enabled,value=true

aws cognito-idp admin-enable-user \
  --user-pool-id USER_POOL_ID \
  --username LEGITIMATE_USERNAME
```

**Validation checklist:**
- [ ] API returning expected responses (test with known-good requests)
- [ ] Error rates returned to pre-incident baseline
- [ ] WAF blocking malicious traffic, no false positives on legitimate users
- [ ] All attacker-created resources removed
- [ ] Vulnerability patched and tested

## Step 7: Hardening Recommendations

Present to user:

- [ ] WAF associated with ALL API stages (with managed rule groups enabled)
- [ ] Rate-based rules configured per endpoint based on expected traffic
- [ ] API Gateway access logging and execution logging enabled
- [ ] Request validation enabled (models, parameter checking)
- [ ] Authorizers tested and covering all endpoints
- [ ] CORS restricted to authorized origins only
- [ ] X-Ray tracing enabled for request troubleshooting
- [ ] CloudWatch alarms on 4xx/5xx error rate spikes
- [ ] Regular API security assessments scheduled
- [ ] GuardDuty Lambda Protection / Runtime Monitoring enabled on backend compute

## Escalation Triggers

- Confirmed data exfiltration via API → Legal + compliance
- Backend compute compromised (Lambda, ECS) → Route to `ai-irp-ec2-compromise.md`
- Attacker created IAM credentials → Route to `ai-irp-credential-compromise.md`
- SSRF accessing IMDS credentials → Route to `ai-irp-sts-token-abuse.md`
- DDoS / sustained resource exhaustion → Consider AWS Shield Advanced engagement

## Reference

Full human playbook: `IRP-APISecurityBreach.md` *(planned — PR4/PR7)*
OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x11-t10/
