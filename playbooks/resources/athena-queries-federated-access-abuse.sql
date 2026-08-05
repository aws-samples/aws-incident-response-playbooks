-- =============================================================================
-- Athena Queries: Federated Access Abuse Investigation
-- Companion resource for IRP-FederatedAccessAbuse.md
-- =============================================================================
-- Prerequisites:
--   - CloudTrail logs delivered to S3 and queryable via Athena
--   - Replace placeholder values: START_TIME, END_TIME, FEDERATED_ROLE_NAME,
--     SUSPICIOUS_IP_1, SUSPICIOUS_IP_2, ROLE_SESSION_NAME
--   - Adjust table name (cloudtrail_logs) to match your Athena table
-- =============================================================================


-- ---------------------------------------------------------------------------
-- 1. All federated role assumptions (SAML and OIDC) in a time window
-- Purpose: Identify all sessions established via federation, including source
--          IPs and user agents, to distinguish legitimate from unauthorized use
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, sourceIPAddress, userAgent,
       userIdentity.arn AS assumedRoleArn,
       requestParameters AS requestParams,
       responseElements,
       additionalEventData
FROM cloudtrail_logs
WHERE eventName IN ('AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 2. Console logins via federation with source IP analysis
-- Purpose: Identify federated console sessions and check for logins from
--          unexpected geographic locations or IP ranges
-- ---------------------------------------------------------------------------
SELECT eventTime, sourceIPAddress,
       userIdentity.arn AS principalArn,
       additionalEventData AS loginDetails,
       userAgent,
       awsRegion
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
  AND additionalEventData LIKE '%SamlProviderArn%'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 3. SAML and OIDC provider configuration changes (creation, update, deletion)
-- Purpose: Detect unauthorized modifications to federation trust — a new or
--          modified provider may indicate the threat actor is establishing
--          their own trust relationship
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, userIdentity.arn AS actor,
       sourceIPAddress, requestParameters, responseElements
FROM cloudtrail_logs
WHERE eventName IN ('CreateSAMLProvider', 'UpdateSAMLProvider', 'DeleteSAMLProvider',
                    'CreateOpenIDConnectProvider', 'DeleteOpenIDConnectProvider',
                    'AddClientIDToOpenIDConnectProvider',
                    'UpdateOpenIDConnectProviderThumbprint')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 4. All actions taken during federated sessions from suspicious source IPs
-- Purpose: Once suspicious IPs are identified from queries 1–2, use this to
--          determine the full scope of what the threat actor did
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, eventSource, sourceIPAddress,
       userIdentity.arn AS sessionArn,
       requestParameters, errorCode
FROM cloudtrail_logs
WHERE userIdentity.sessionContext.sessionIssuer.type = 'Role'
  AND userIdentity.sessionContext.sessionIssuer.arn LIKE '%FEDERATED_ROLE_NAME%'
  AND sourceIPAddress IN ('SUSPICIOUS_IP_1', 'SUSPICIOUS_IP_2')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 5. Detect new or recently modified identity providers across all accounts
-- Purpose: Run against organization-wide CloudTrail to identify if the threat
--          actor created federation trust in other accounts
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, recipientAccountId, userIdentity.arn AS actor,
       sourceIPAddress, requestParameters
FROM cloudtrail_logs
WHERE eventName IN ('CreateSAMLProvider', 'CreateOpenIDConnectProvider',
                    'UpdateSAMLProvider', 'UpdateOpenIDConnectProviderThumbprint')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 6. Unique source IPs for federated sessions (anomaly identification)
-- Purpose: Aggregate source IPs to identify unfamiliar addresses — compare
--          against known corporate egress ranges to spot unauthorized sessions
-- ---------------------------------------------------------------------------
SELECT sourceIPAddress, COUNT(*) AS session_count,
       MIN(eventTime) AS first_seen, MAX(eventTime) AS last_seen,
       array_agg(DISTINCT json_extract_scalar(requestParameters, '$.roleArn')) AS roles_assumed
FROM cloudtrail_logs
WHERE eventName IN ('AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
GROUP BY sourceIPAddress
ORDER BY session_count DESC;


-- ---------------------------------------------------------------------------
-- 7. All actions performed by a specific federated session
-- Purpose: Use the role session name from AssumeRoleWithSAML response to trace
--          exactly what a specific session did
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, eventSource, sourceIPAddress,
       requestParameters, responseElements, errorCode
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%ROLE_SESSION_NAME%'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 8. Privilege escalation attempts during federated sessions
-- Purpose: Detect if the threat actor attempted to create persistence or
--          escalate permissions during their federated session
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, sourceIPAddress,
       userIdentity.arn AS actor,
       requestParameters, errorCode
FROM cloudtrail_logs
WHERE userIdentity.sessionContext.sessionIssuer.type = 'Role'
  AND eventName IN ('CreateUser', 'CreateRole', 'CreateAccessKey',
                    'AttachRolePolicy', 'AttachUserPolicy', 'PutRolePolicy',
                    'PutUserPolicy', 'CreatePolicyVersion',
                    'UpdateAssumeRolePolicy', 'CreateSAMLProvider',
                    'UpdateSAMLProvider', 'CreateLoginProfile')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 9. Federated sessions with unusual duration or attribute patterns
-- Purpose: Identify sessions with maximum duration configured (12h) or
--          sessions assumed into roles the user doesn't normally access
-- ---------------------------------------------------------------------------
SELECT eventTime, sourceIPAddress,
       json_extract_scalar(requestParameters, '$.roleArn') AS targetRole,
       json_extract_scalar(requestParameters, '$.durationSeconds') AS sessionDuration,
       json_extract_scalar(requestParameters, '$.principalTags') AS principalTags,
       userAgent
FROM cloudtrail_logs
WHERE eventName IN ('AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
