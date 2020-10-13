# Incident Response Run-book Template

### Incident Type

Unintended access to an S3 Bucket

### Summary

This runbook is provided to be used as a template only. It should be customized by administrators working with AWS to suit their particular needs, risks, available tools and work processes. It is not official AWS documentation and is provided as-is to customers using AWS products and who are looking to improve their incident response capability.

The run-book included below covers one of several common scenarios faced by AWS customers. It outlines steps based on the [NIST Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) (Special Publication 800-61 Revision 2) that can be used to:

* Gather evidence
* Contain and then eradicate the incident
* recover from the incident
* Conduct post-incident activities, including post-mortem and feedback processes

Interested readers may also find the AWS Security Incident Response Guide (first published in June 2019) a useful guide as an overview of how the below steps were created.

Each run-book corresponds to a unique incident and there are 5 parts to handling each incident type, following the NIST guidelines referenced above. Each part corresponds to an action in the NIST handling guide.

Once you have customized the runbook to meet your needs, it is important that you test them (for example, in Game Days) prior to publishing within your knowledge management system and that all necessary personnel are familiar with the actions required to respond to an incident.

Note that some of the incident response steps noted below may incur costs in your AWS account(s) for services used in either preparing for, or responding to incidents. Customizing this runbook and testing it will help you to determine if additional costs will be incurred. You can use [AWS Cost Explorer](https://aws.amazon.com/aws-cost-management/aws-cost-explorer/) and look at costs incurred over a particular time frame (such as when running Game Days) to establish what the possible impact might be.

The next section “Incident Handling Process” will cover the five steps (parts 1 - 5) for handling unintended access to an S3 bucket.

## Incident Handling Process

### Part 1: Gather evidence

1. You are made aware that there has been a possible unintended data access from an Amazon Simple Storage Service (Amazon S3, or just S3) bucket. This information could come via different means:
    1. An internal ticketing system (the sources of the ticket are varied and could include any of the means below)
    2. A message from a contractor or third-party service provider
    3. From an alert in one of your own monitoring systems (for example, in AWS, this might include an AWS Config managed rule, AWS CloudTrail via Event Bridge or CloudWatch Events and SNS, via GuardDuty, Security Hub or a similar service)
    4. From an attacker (for example, requesting a ransom or they will disclose further data)
    5. Via an anonymous tip
    6. From a public news article in the press, on a blog or in the news
2. At this point, you may not know if the data leak is due to a miss-configured bucket, or a set of leaked credentials:
    1. Use [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html) to determine if any S3 buckets may have overly permissive configuration, giving unintended access to unauthorized principals
    2. Use IAM Access Analyzer to determine if any IAM role trust policy provides unintended access to principals in the same or other AWS accounts
    3. [Review CloudTrail logs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html) to determine if recent (prior to breach date, if known) changes had been made to bucket configuration, such as the bucket’s Block All Public Access settings, object ACLs, or bucket policies. You may choose to do this using a tool such as [Amazon Athena](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html#tips-for-querying-cloudtrail-logs)
    4. Review CloudTrail logs to determine if recent (prior to breach date, if known) changes have been made to IAM role trust policies
3. If you are already aware of the S3 bucket(s) involved, Firstly move to **Part 2** to contain the incident. Once that is done, return here and then move on to step 5. If you have not established which bucket(s) are involved, continue to step 4.
4. If you do not know which bucket is involved:
    1. If you do not know which bucket is involved, but do know which data is involved:
        1. Use internal tools that links that data to a bucket, such as checking a Configuration Management Database (CMDB)
        2. Use the [S3 ls command](https://docs.aws.amazon.com/cli/latest/userguide/cli-services-s3-commands.html#using-s3-commands-listing-buckets) from the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html) to list out the contents of your S3 bucket(s). For buckets with many objects, you can filter by specifying specific key prefixes in the ls command. This will be especially useful if you already know the data objects involved
        3. There are several common third-party tools that can also be used to search though files in Amazon S3
        4. Query CloudTrail Data Event logs for one of the files in question, and determine the name of the bucket from the CloudTrail event. [You can do this using Amazon Athena](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html#query-examples-cloudtrail-logs) This will also provide you the identity of the principal making the API call
    2. If you do not know specifically which bucket or which data was involved, there are several options:
        1. If you know the set of credentials involved, search CloudTrail **Data Events** using a tool such as Amazon Athena, filtering on that set of credentials and [s3.amazonaws.com](http://s3.amazonaws.com/) as the event source. If you do not have an Amazon Athena table already configured, you can [quickly set one up from the AWS CloudTrail console](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html#create-cloudtrail-table-ct).
        2. Review [CloudTrail Insights](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-insights-events.html) (this must be enabled prior to the event) to determine if any insights have been generated that may relate to the time and date of the breach, and determine which resources were involved by drilling down into the events highlighted by the specific insight. This will also provide the user identity of the principal that accessed the object(s)
        3. Simply go to the Amazon S3 console and review the “**Access**” column in the table listing all S3 buckets (under the **Buckets** menu). If the column lists a value of **Public** for a bucket, this means that unauthenticated users have access to objects in the bucket, by virtue of object ACLs or the bucket’s bucket policy. This is a useful approach for a single account
        4. If you want to check across multiple accounts in an AWS Organization, you can use Amazon Macie. Go to the Macie console and select **Summary** from the navigation menu. Review the percentage of buckets that are publicly accessible under the **Public** heading of the first table. Next, review the number of buckets that are shared with other AWS accounts by reviewing the information under the **Shared** heading of the first table.
5. If the buckets are under your administrative control (either in an AWS account you control, or in an AWS account for which you have authorization and appropriate access, for example via an IAM Role), move ahead to **Part 2** to contain the incident, then return to this point and move on to step 7. If they are not under your administrative control, move on to step 6
6. If you do not have administrative control of the S3 buckets involved, you will need to establish a communication channel with the provider/team/individual that does. This may involve opening a new case on the provider’s service platform, contacting their customer service, directly contacting your technical point of contact (PoC) in that organization, or something similar. Do this as a matter of urgency, as in Part 2, below, you will need to request that they take action to contain the incident
7. Confirm a ticket/case has been raised for the incident. If not, manually raise one.
8. Determine if any user cases are already open for the bucket(s) that can be correlated to any notifications or data you already have in relation to the incident. Document any noted end-user impact/experience of the issue in the relevant ticket. These may include (but not be limited to):
    1.  Files missing from the bucket
    2. Unfamiliar new files in the bucket
    3. Files that have had their access settings (such as ACLs) changed, in particular where those files have been made public
    4. Modified bucket permissions, ACLs, Block Public Access settings (all less likely to be noted by regular users, but possible)
9. In the case of automatically created tickets/cases, determine what internal alarms/metrics are currently indicating an issue (what caused the ticket to be created? - see 1a, above)
10. Determine the application impacted (if any, this may be done quickly via Resource Tags, or by using your CMDB)
11. Determine if there are any known events that could be causing service disruption (for example, an application change roll-out that is now resulting in the mishandling API interactions with the S3 bucket. This could include but may not be limited to:
    1. Writing incorrect files to the bucket
    2. Incorrectly deleting files from the bucket
    3. Modifying file or bucket permissions, ACLs, or Block Public Access settings
12. Determine for the bucket and/or data in question, what is the [data classification](https://d1.awsstatic.com/whitepapers/compliance/AWS_Data_Classification.pdf) of the data that has been (or allegedly has been) leaked? The classification level may determine the incident response path taken, however the remainder of this run book will assume that the classification of the data indicates some level of business impact (whether reputational, financial or other). This classification may be recorded in your CMDB or a specific data classification document.
13. Internal Communications:
    1. Identify stakeholder roles from the application entry in the Configuration Management Database (CMDB) entry for that application, or via the application’s risk register
    2. Open a conference bridge war room for the incident
    3. Notify identified stakeholders including (if required) legal personnel, technical teams and developers and add them to the ticket and the war room, so they are updated as the ticket is updated
14. External Communications (for the relevant team/people, not necessarily the first responder - most likely legal, PR, board, C-levels, etc.):
    1. Identify customers that could have/are impacted by the data leak
    2. Identify customer data that could have been leaked as a result of the data leak
    3. Compile this information and *securely* distribute it to the relevant people (for example, using a corporate file share where permissions and access can be controlled)
        
        Those teams/individuals will also likely identify public domain material (news articles, blog posts, tweets, etc.) that mention the leak and determine if/how to respond to these (are they factually correct? How much information can be shared and at what time so as not to compromise any ongoing or future investigations? Are there any potential legal ramifications that need to be considered when responding? etc.). This is not a task for the responder and should not distract that person from the immediate task of handling the technical aspects of the incident.

### Part 2: Contain The Incident

By now ideally it will have been established that there is an incident and whether the compromise relates to a set of leaked credentials, miss-configured bucket policies, modified object ACLs, or a combination of these. Firstly, disable compromised credentials or revoke permissions associated with those credentials, thereby preventing any further API activity using the compromised credentials. Next, move on to bucket policies (if relevant). Finally, move on to Block Public Access settings.

1. For the **compromised credential** details obtained from reviewing CloudTrail logs in Part 1, disable those credentials if they are from AWS accounts under your administrative control
    1. If they are long term IAM user credentials, [disable them using the IAM console or API](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
    2. If they are short term credentials obtained via STS they will be associated with an IAM role. There are a couple of options available to disable these:
        1. [Revoke all current roles sessions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html) (note that if the attacker has the ability to obtain new credentials, this won’t solve the problem)
        2. If the attacker is able to obtain another set of credentials and the activity continues, it will then be necessary to remove all IAM policies attached to the role, modify the attached policies to block all access, or modify the role’s trust policy to prevent the attacker from assuming the role. As the credentials will remain valid for the specified time duration once issued, it is important to note that modifying the trust policy will allow any current valid credentials to continue to be used whilst still valid
            **Note that the above actions will stop all users from using credentials obtained by assuming the role, including any legitimate users or applications**
        3. If the role is attached to an EC2 instance, you will also need to review credentials related to the instance (for example, private/public key pairs used for SSH) to ensure that these have not also been compromised, allowing an attacker to access an S3 bucket using the role credentials attached to the instance. Two key vectors:
            1. A user can gain access to an EC2 instance using a set of credentials (private key) that allows them to SSH to the instance
            2. The instance is being used as a reverse proxy, or behind certain types of web application firewalls, or has a role that is directly or indirectly internet-facing and a malicious user performs a Server-side Request Forgery (SSRF) with the goal of having the instance’s application simply repeat the request to S3 and return the output 
2. The compromised credentials should now be disabled. Verify this by checking the CloudTrail console for the next 30 minutes or so for ongoing credential use, whether by access key, IAM user, or Role.
3. If the credentials used to obtain data are not under your administrative control, and the access was obtained using credentials (i.e., **not** anonymous access) this means that the **bucket policy** is too permissive. This is because IAM roles or users from other AWS accounts will also need permissions to access a bucket in your account via the bucket policy. Therefore, it is necessary to modify the bucket’s bucket policy:
    1. From the bucket(s) identified in Part 1, review the bucket policies to determine which principals have access to the buckets for data plane and/or management plane operations:
        1. **Do this first**: You will need to modify control plane access to prevent unauthorized users from making changes to the bucket’s configuration (bucket policies, bucket ACL, bucket or account level Block Public Access settings)
        2. You will need to modify data plane access Put*/Get* to prevent unauthorized users from accessing data that they should not have access to, for all applicable read and write operations
        3. For specific objects of concern, identify any AWS accounts or predefined groups listed as having permission in the [object’s ACL](https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html) (IAM users cannot be listed individually in an ACL). Another approach (if your permission model does not involve ACLs) is to modify the ACLs for all objects in the bucket to remove all other accounts or predefined groups and simply apply FULL_CONTROL to the bucket owner only (not the object owner - potentially from a different AWS account)
4. If the issue is that the bucket allows public (unauthenticated) access to objects, either via ACLs, the bucket policy (“principal”: “*”) or a combination thereof, such settings will need to be modifed:
    1. the quickest way to remove this access is to modify the bucket’s **Block All Public Access** configuration. However note this will impact **all** objects in the bucket, not just the one(s) you are concerned with
    2. For each bucket, in the Amazon S3 console, go to the object, select it and then click on **Permissions >> Access Control List**. There will be a note on the Access Control List button indicating public access. Check the **Everyone** radio button under the **Public access** row and then remove the checks in the boxes in the ACL’s settings. Finally, click **Save. **Note that this doesn’t modify
    3. For each object, in the Amazon S3 console, go to the object, select it and then click on **Permissions**. Under the **Public access** row, select the **Everyone** radio button and uncheck all the boxes in the resulting object ACL properties box and click **Save**. If many objects are involved, it will be quicker to use either the [AWS CLI or one of the AWS SDKs](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectAcl.html).

### Part 3: Eradicate the Incident

Key components of the eradication process include the following:

1. Mitigate any vulnerabilities that were exploited
2. Rotate compromised passwords/credentials

Most of the steps in this section are taken from the [security best practices for Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/dev/security-best-practices.html). Check back with that document frequently for updates.


1. Eradicate any attack vectors related to systems writing to or reading from the S3 bucket(s). It is likely that you will have applications that are writing to or reading from an S3 bucket. As per Part 2, If an attacker has gained access to systems that are writing to a bucket (for example, an EC2 instance), The attacker could now effectively use the instance’s credentials (via the AWS CLI or SDK) on an application instance, for example, to read data from the bucket:
    1. [Configure IMDSv2](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/) on all application instances/role holding instances
    2. [Rotate SSH credentials](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html) for EC2 Linux
    3. Update user passwords for domain or local users using Microsoft Windows Remote Desktop Protocol (RDP) and verify users in the Remote Desktop Users group within Windows and/or Group Policy (for example, if you are adding Active Directory Global Security Groups to the Remote Desktop Users group on local operating systems, a fairly common Group Policy task)
2. Mitigate vulnerabilities related to your service configurations. For example, with S3, determine which configuration items need to be updated:
    1. Return modified object ACLs to their secure settings, removing unauthenticated access permissions
    2. Implement least privilege in bucket policies
    3. Ensure only appropriate principals have permission to perform data or control plane operations on the bucket
    4. Ensure IAM policies are appropriately scoped and if necessary, [Permission Boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html) and/or [Service Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html) have been deployed appropriately
    5. Encrypt data at rest using [Amazon S3 Server Side Encryption](https://docs.aws.amazon.com/AmazonS3/latest/dev/serv-side-encryption.html) - this protects the data at rest, and means that principals must have permissions in **both **S3 and AWS KMS (the KMS Customer Master Key (CMK) key policy) to access the data
    6. [Enable versioning](https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html) in S3 to enable data recovery, and consider:
    7. [Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock.html) to prevent the deletion of critical data
3. If credential compromise was involved:
    1. Flag for review the process for handling user credentials during Move/Add/Change (MAC) procedures for the post-incident activity
    2. The offending credentials should have been disabled in Part 2, you may now consider issuing new credentials to impacted users
    3. Close down/remove user accounts or roles if they are not valid accounts/roles (or IAM IdPs, AWS SSO instances, etc.)
    4. Enable MFA Delete for S3
    5. If you have objects that need to be public, rather than setting the ACL so that the object is world-readable, consider using an S3 pre-signed URL with a suitable expiry time and have your application pass that to the unauthenticated user to allow them to access the object.

### Part 4: Recover from the Incident

With S3 best practices now in place, the next step is to determine if the attack has been mitigated, or if additional tuning is needed to eradicate the attack. This includes reviewing pre- and post-mitigation logs to:

* Determine the impact of the mitigations already performed
* Identify any other attack signatures to attempt to eradicate or further mitigate the attack

Once this has been completed, it will likely be necessary to restore any lost or corrupted data.

Restore lost or modified data:

1. If you have [S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html), [restore an earlier version of the object](https://docs.aws.amazon.com/AmazonS3/latest/dev/RestoringPreviousVersions.html) to replace the modified object. If the object has been deleted using a simple delete command (without specifying a version ID for the object, it will now have a [delete marker](https://docs.aws.amazon.com/AmazonS3/latest/dev/DeleteMarker.html) in place of the object. you can [delete the delete marker](https://docs.aws.amazon.com/AmazonS3/latest/dev/RemDelMarker.html) to recover the object
2. If the object was deleted and the delete command specified an object Version ID, that version of the object will be permanently deleted. You will need to establish if previous versions of the object still exist, or of the object can be retrieved from another location (see below steps)
3. If you move data to other S3 storage classes (S3 IA, Glacier, etc.) as part of a back-up or archival process, determine if the files still exist in that storage class and retrieve them (remember that files *can be deleted* from other storage classes). [Lifecycle policies](https://docs.aws.amazon.com/AmazonS3/latest/dev/lifecycle-transition-general-considerations.html) are used to move objects between storage classes
4. If you are using S3 Cross Region Replication (CRR) restore the data from the target bucket to the source bucket as necessary
5. If none of the previous actions allow you to restore the deleted or modified data, you will need to determine if the data is retrievable from another source (such as an on-premise system or an S3 bucket in a different account

From the logs obtained in PART 1, review those obtained at the time of the initial investigation. Now that mitigation has been placed, you need to go back and obtain those metrics and logs again, and compare them to the incident metrics and logs obtained earlier.

If data plane activity has returned to pre-attack levels and the logs show no further evidence of malicious use, the attack has been mitigated (at least for now). Continue to monitor the service post-attack; if suspicious data plane activity reoccurs, take the following steps:

1.  return to Part 1 and follow those steps again
2. Review logs and related data to determine if you have correctly identified the attack vector, or if the attacker has changed the vector in response to the mitigation

### Part 5: Post-Incident Activity

This “sharpen the saw” activity allows teams to assess their response to the actual incident, determine what worked and what didn’t, update the process based on that information and record these findings.


1. Review how the incident was handled, as well as the incident handling process generally, with key stakeholders identified in Part 1.
2. Document lessons learned, including attack vector(s) mitigation(s), misconfiguration, etc.
3. Store the artifacts from this process with the application information in the CMDB entry for the application and also in the CMDB entry for the S3 bucket and the data leak incident response process.
4. Update risk documents based on any newly discovered threat/vulnerability combinations that were discovered as a result of lessons learned
5. If new application or infrastructure configuration is required to mitigate any newly identified risks, conduct these change activities and update application and component configuration in the CMDB
6. Ask the following questions and assign people to resolve any issues that come up as a result:
    1. What information would have helped me respond to this incident more swiftly?
    2. What detection would have alerted me to the issue sooner?
    3. What configuration (technical or process) would have prevented this data being exposed in this way?
    4. What automation, tooling or access would have made it easier to investigate the root cause?
7. For any actions that are raised as the result of parts 3, 4 and 5, assign those actions and follow up to ensure they are completed

