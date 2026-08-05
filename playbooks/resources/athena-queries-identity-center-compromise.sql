-- =============================================================================
-- Athena Queries: Identity Center Compromise Investigation
-- Companion resource for IRP-IdentityCenterCompromise.md
-- =============================================================================
-- Prerequisites:
--   - CloudTrail logs delivered to S3 and queryable via Athena
--   - Replace placeholder values: START_TIME, END_TIME, SUSPECTED_ADMIN,
--     MGMT_ACCOUNT_ID, ATTACKER_USER_ID, SUSPICIOUS_IP_1, SUSPICIOUS_IP_2
--   - Adjust table name (cloudtrail_logs) to match your Athena table
--   - Identity Center events are logged in the region where Identity Center
--     is configured (typically us-east-1)
-- =============================================================================


-- ---------------------------------------------------------------------------
-- 1. All Identity Center administrative actions in a time window
-- Purpose: Broad sweep of all Identity Center API activity to identify
--          unauthorized changes to permission sets, account assignments,
--          and identity store entities
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, eventSource, sourceIPAddress, userAgent,
       userIdentity.arn AS actor_arn, requestParameters, responseElements, errorCode
FROM cloudtrail_logs
WHERE eventSource IN ('sso.amazonaws.com', 'identitystore.amazonaws.com',
                      'sso-directory.amazonaws.com')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 2. Permission set creation and modification events
-- Purpose: Identify unauthorized permission sets created by the threat actor
--          or legitimate permission sets that were modified to escalate
--          privileges (e.g., attaching AdministratorAccess)
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, sourceIPAddress, userIdentity.arn AS actor_arn,
       json_extract_scalar(requestParameters, '$.name') AS permission_set_name,
       requestParameters, responseElements
FROM cloudtrail_logs
WHERE eventSource = 'sso.amazonaws.com'
  AND eventName IN ('CreatePermissionSet', 'UpdatePermissionSet',
                    'DeletePermissionSet', 'AttachManagedPolicyToPermissionSet',
                    'DetachManagedPolicyFromPermissionSet',
                    'PutInlinePolicyToPermissionSet', 'DeleteInlinePolicyFromPermissionSet',
                    'AttachCustomerManagedPolicyReferenceToPermissionSet',
                    'PutPermissionsBoundaryToPermissionSet')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 3. Account assignment changes (who got access to which accounts)
-- Purpose: Determine which AWS accounts the threat actor granted themselves
--          or backdoor users access to — this defines the scope of impact
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, sourceIPAddress, userIdentity.arn AS actor_arn,
       json_extract_scalar(requestParameters, '$.targetId') AS account_id,
       json_extract_scalar(requestParameters, '$.permissionSetArn') AS permission_set_arn,
       json_extract_scalar(requestParameters, '$.principalId') AS principal_id,
       json_extract_scalar(requestParameters, '$.principalType') AS principal_type
FROM cloudtrail_logs
WHERE eventSource = 'sso.amazonaws.com'
  AND eventName IN ('CreateAccountAssignment', 'DeleteAccountAssignment')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 4. User and group membership changes in the identity store
-- Purpose: Detect backdoor users or groups created by the threat actor, and
--          unauthorized group membership additions granting elevated access
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, eventSource, sourceIPAddress,
       userIdentity.arn AS actor_arn, requestParameters, responseElements
FROM cloudtrail_logs
WHERE eventSource = 'identitystore.amazonaws.com'
  AND eventName IN ('CreateUser', 'DeleteUser', 'UpdateUser',
                    'CreateGroup', 'DeleteGroup', 'CreateGroupMembership',
                    'DeleteGroupMembership')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 5. SSO authentication events from unusual source IPs
-- Purpose: Identify active SSO sessions from threat actor infrastructure
--          (requires CloudTrail data events for Identity Center)
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, sourceIPAddress, userAgent,
       userIdentity.principalId AS sso_user,
       json_extract_scalar(additionalEventData, '$.MFAUsed') AS mfa_used
FROM cloudtrail_logs
WHERE eventSource = 'sso.amazonaws.com'
  AND eventName IN ('Authenticate', 'Federate', 'ListAccounts',
                    'ListAccountRoles', 'GetRoleCredentials')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 6. All Identity Center actions by a specific principal
-- Purpose: Once a compromised admin is identified, trace all their Identity
--          Center activity to determine the full scope of changes made
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, eventSource, sourceIPAddress, userAgent,
       errorCode, requestParameters, responseElements
FROM cloudtrail_logs
WHERE userIdentity.arn = 'arn:aws:iam::MGMT_ACCOUNT_ID:user/SUSPECTED_ADMIN'
  AND eventSource IN ('sso.amazonaws.com', 'identitystore.amazonaws.com',
                      'sso-directory.amazonaws.com')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 7. Permission set policy attachment history
-- Purpose: Review all managed and inline policy changes to permission sets
--          during the incident window — compare against baseline to identify
--          privilege escalation
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName,
       json_extract_scalar(requestParameters, '$.permissionSetArn') AS permission_set_arn,
       json_extract_scalar(requestParameters, '$.managedPolicyArn') AS managed_policy_arn,
       sourceIPAddress, userIdentity.arn AS actor
FROM cloudtrail_logs
WHERE eventSource = 'sso.amazonaws.com'
  AND eventName IN ('AttachManagedPolicyToPermissionSet',
                    'DetachManagedPolicyFromPermissionSet',
                    'PutInlinePolicyToPermissionSet',
                    'DeleteInlinePolicyFromPermissionSet')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 8. Identify all accounts accessed via SSO by a specific user
-- Purpose: Determine which accounts the threat actor (or backdoor user)
--          actually accessed via SSO portal after creating assignments
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, sourceIPAddress,
       json_extract_scalar(requestParameters, '$.accountId') AS target_account,
       json_extract_scalar(requestParameters, '$.roleName') AS role_name
FROM cloudtrail_logs
WHERE eventSource = 'sso.amazonaws.com'
  AND eventName = 'GetRoleCredentials'
  AND userIdentity.principalId LIKE '%ATTACKER_USER_ID%'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 9. High-volume Identity Center API calls (potential automated attack)
-- Purpose: Detect bulk operations that suggest the threat actor used scripts
--          or automation to rapidly create assignments across many accounts
-- ---------------------------------------------------------------------------
SELECT eventName, eventSource, COUNT(*) AS call_count,
       sourceIPAddress, userIdentity.arn AS actor
FROM cloudtrail_logs
WHERE eventSource IN ('sso.amazonaws.com', 'identitystore.amazonaws.com')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
GROUP BY eventName, eventSource, sourceIPAddress, userIdentity.arn
HAVING COUNT(*) > 10
ORDER BY call_count DESC;


-- ---------------------------------------------------------------------------
-- 10. Delegated administrator changes
-- Purpose: Detect if the threat actor registered or deregistered delegated
--          administrators for Identity Center — this can shift administrative
--          control to an account the threat actor controls
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, sourceIPAddress, userIdentity.arn AS actor,
       json_extract_scalar(requestParameters, '$.accountId') AS target_account,
       json_extract_scalar(requestParameters, '$.servicePrincipal') AS service_principal
FROM cloudtrail_logs
WHERE eventName IN ('RegisterDelegatedAdministrator', 'DeregisterDelegatedAdministrator')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;

