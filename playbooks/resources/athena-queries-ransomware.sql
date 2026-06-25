-- =============================================================================
-- Athena Queries: Ransomware Investigation
-- Companion resource for IRP-Ransomware.md
-- =============================================================================
-- Prerequisites:
--   - CloudTrail logs delivered to S3 and queryable via Athena
--   - Replace placeholder values: SUSPECTED_PRINCIPAL, START_TIME, END_TIME
--   - Adjust table name (cloudtrail_logs) to match your Athena table
-- =============================================================================


-- ---------------------------------------------------------------------------
-- 1. KMS key creation and encryption operations by a suspect principal
-- Purpose: Detect threat actor creating attacker-controlled KMS keys and using
--   them to encrypt resources. This is the primary indicator for EBS volume
--   encryption ransomware (Pattern 1 in Appendix E).
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, userIdentity.arn, awsRegion,
       requestParameters, responseElements, sourceIPAddress
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%SUSPECTED_PRINCIPAL%'
  AND eventSource = 'kms.amazonaws.com'
  AND eventName IN ('CreateKey', 'CreateGrant', 'Encrypt', 'ReEncryptFrom',
                    'ReEncryptTo', 'GenerateDataKey', 'GenerateDataKeyWithoutPlaintext',
                    'ScheduleKeyDeletion', 'DisableKey', 'PutKeyPolicy')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 2. Bulk deletion activity across S3, EBS, and RDS
-- Purpose: Identify destructive actions across multiple services. Ransomware
--   actors typically delete snapshots, suspend versioning, and destroy backups
--   to eliminate recovery options before demanding payment.
-- ---------------------------------------------------------------------------
SELECT eventTime, eventSource, eventName, userIdentity.arn,
       requestParameters, sourceIPAddress, awsRegion
FROM cloudtrail_logs
WHERE eventName IN ('DeleteObject', 'DeleteObjects', 'DeleteSnapshot',
                    'DeleteDBSnapshot', 'DeleteDBClusterSnapshot',
                    'DeleteRecoveryPoint', 'DeleteBackupVault',
                    'PutBucketVersioning', 'DeleteBucketPolicy')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 3. Snapshot operations (deleted, copied, or shared)
-- Purpose: Track snapshot manipulation — threat actors may delete snapshots
--   to prevent recovery, or share/copy them to exfiltrate data before
--   encrypting (double extortion).
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, userIdentity.arn, awsRegion,
       requestParameters, responseElements, errorCode
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName IN ('DeleteSnapshot', 'ModifySnapshotAttribute',
                    'CopySnapshot', 'CreateSnapshot', 'CreateSnapshots')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 4. S3 versioning suspension and Object Lock modifications
-- Purpose: Detect threat actor disabling protective controls before deletion.
--   Versioning suspension followed by bulk deletion is a signature pattern
--   for S3 ransomware (Pattern 2 in Appendix E).
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, userIdentity.arn,
       requestParameters, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketVersioning', 'PutObjectLockConfiguration',
                    'PutBucketLifecycleConfiguration', 'DeleteBucketPolicy',
                    'PutBucketPolicy')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 5. All KMS operations in a time window
-- Purpose: Broad KMS activity sweep to detect threat actor key creation and
--   usage patterns. Useful when the specific principal is not yet identified.
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, userIdentity.arn, awsRegion,
       requestParameters, responseElements, sourceIPAddress, errorCode
FROM cloudtrail_logs
WHERE eventSource = 'kms.amazonaws.com'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 6. High-volume deletion activity (ransomware indicator)
-- Purpose: Identify principals performing bulk delete operations. Any principal
--   with >10 delete calls in the incident window warrants investigation.
-- ---------------------------------------------------------------------------
SELECT eventSource, eventName, userIdentity.arn,
       COUNT(*) as call_count, MIN(eventTime) as first_seen, MAX(eventTime) as last_seen
FROM cloudtrail_logs
WHERE eventName LIKE 'Delete%'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
GROUP BY eventSource, eventName, userIdentity.arn
HAVING call_count > 10
ORDER BY call_count DESC;


-- ---------------------------------------------------------------------------
-- 7. S3 bucket versioning changes
-- Purpose: Detect versioning being disabled — a precursor to bulk deletion
--   in S3 ransomware attacks. Versioning suspension makes deleted objects
--   unrecoverable.
-- ---------------------------------------------------------------------------
SELECT eventTime, userIdentity.arn, requestParameters, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'PutBucketVersioning'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;


-- ---------------------------------------------------------------------------
-- 8. Cross-account snapshot sharing (data exfiltration via snapshots)
-- Purpose: Detect threat actor sharing snapshots to external accounts before
--   deleting them — the double-extortion pattern where data is exfiltrated
--   via snapshot sharing before the encryption/deletion phase.
-- ---------------------------------------------------------------------------
SELECT eventTime, eventName, userIdentity.arn, requestParameters, responseElements
FROM cloudtrail_logs
WHERE eventName IN ('ModifySnapshotAttribute', 'ModifyDBSnapshotAttribute',
                    'ModifyDBClusterSnapshotAttribute')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
