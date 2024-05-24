# Incident Response Playbook Template

### Incident Type

Classified or Protected Data Spill/Leakage

### Introduction

This playbook is provided as a template to customers using AWS products and who are building their incident response capability.  You should customize this template to suit your particular needs, risks, available tools and work processes.

Security and Compliance is a shared responsibility between you and AWS. AWS is responsible for “Security of the Cloud”, while you are responsible for “Security in the Cloud”. For more information on the shared responsibility model, [please review our documentation](https://aws.amazon.com/compliance/shared-responsibility-model/). Classified data spillage in the cloud as the result of resource misconfiguration, or mishandling by users within the environment falls on the customer side of the dual responsibility model. 

You are responsible for making your own independent assessment of the information in this document. This document: (a) is for informational purposes only, (b) references current AWS product offerings and practices, which are subject to change without notice, and (c) does not create any commitments or assurances from AWS and its affiliates, suppliers or licensors. This document is provided “as is” without warranties, representations, or conditions of any kind, whether express or implied. The responsibilities and liabilities of AWS to its customers are controlled by AWS agreements, and this document is not part of, nor does it modify, any agreement between AWS and its customers.

## Summary

### This Playbook
This playbook outlines response steps for Data Spill/Leakage incidents.  These steps are based on the [NIST Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) (Special Publication 800-61 Revision 2) that can be used to:

* Gather evidence
* Contain and then eradicate the incident
* Recover from the incident
* Conduct post-incident activities, including post-mortem and feedback processes

Interested readers may also refer to the [AWS Security Incident Response Guide]( https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html) which contains additional resources.

It is important that you routinely test this playbook (e.g., Game Days) and any automation (functional tests), update as necessary to achieve the desired results, and then publish to your knowledge management system and train all responders.

Note that some of the incident response steps noted in each scenario may incur costs in your AWS account(s) for services used in either preparing for, or responding to incidents. Customizing these scenarios and testing them will help you to determine if additional costs will be incurred. You can use [AWS Cost Explorer](https://aws.amazon.com/aws-cost-management/aws-cost-explorer/) and look at costs incurred over a particular time frame (such as when running Game Days) to establish what the possible impact might be.

The next section will provide a summary of this incident type, and then cover the five steps (parts 1 - 5) for handling credential compromise.

### This Incident Type
Data spills/leakage 

**Data Spills**
* Loss, compromise, or suspected compromise of classified information or protected data
* Introduction of classified information to systems not authorized to store or process that information 
* Any mishandling of sensitive, controlled, protected, or restricted information
* Unauthorized disclosure, removal, retention, destruction, or transmission of classified information or protected data
* Breaches of security policy, procedures, rules, or regulations
* PHYSEC, COMSEC, INFOSEC, PERSEC, OPSEC, or CYBER concerns

## Incident Response Process
--- 
### Part 1: Acquire, Preserve, Document Evidence

1. You become aware of a potential data spill. This could come in various forms:
* An internal ticketing system 
* A message from an employee, contractor, or third-party service provider
* Via an anonymous tip
* Via independent or external security researchers
2. Confirm a ticket/case has been raised for the incident. If not, manually raise one. If you do not have a traditional ticketing system, some potential solutions include: 
* A specifically created chat-software channel
* A content management page (Confluence, Sharepoint, etc)
* An email thread

**please note - restrict internal coordination for the incident to those only with a need to know**

3. Determine and begin to document any end-user impact/experience of the issue. From a user’s perspective, for this type of scenario, there may be no direct user impact. Findings should be documented in the ticket/case related to the incident
4. Determine what inter-conected systems have access to the spilled data. Document potential impact from downtime that may occur as a result of removing the data spill and restoring the resource to a previous state.
5. Determine if the data spill is ongoing or was the result of a one-time action. Example: a data stream continuously pushing data to a resource versus an object being uploaded once to an S3 bucket. 
8. Incident Communications:
    1. Identify stakeholder roles from the application entry in the Configuration Management Database (CMDB) entry for that application, or via the application’s risk register
    2. Open a conference bridge war room for the incident
    3. Notify identified stakeholders including (if required) security personnel, legal personnel, technical teams and developers and add them to the ticket and the war room, so they are updated as the ticket is updated
9.	External Communications:
    1. Ensure your organizations legal council is informed and is included in status updates to internal stakeholders and especially in regards to external communications.
    2. For colleagues in the organization that are responsible for providing public/external communication statements, ensure these internal stakeholders are added to the ticket so they receive regular status updates regarding the incident and can complete their own requirements for communications within and external to the business.
    3. If there are regulations in your jurisdiction requiring reporting of such incidents, ensure the people in your organization responsible for notifying local or federal law enforcement agencies are also notified of the event/added to the ticket. Consult your legal advisor and/or law enforcement for guidance on collecting and preserving the evidence and chain of custody.
    4. There may not be regulations, but either open databases, government agencies or NGOs may track this type of activity. Your reporting may assist others

### Part 2: Contain the Incident

The immediate task will be to disable access to the resource where the spilled data is located and remove the spilled data from the environment, thereby preventing any further spillage. After relevant parties are notified of potential downtime, begin the containment steps. 

1. After identifying the source of the data spill, stop any automated processes that (may) continue to push classified data onto an unauthorized system. 
- If it is a human user, add that principal to an IAM user group, or Permission Set that has a DenyAll policy applied to it. Do not remove other permissions as the explicit `Deny` will override any explicit `Allow` permissions. 
- For serverless architectures, apply the AWS managed DenyAll policy to any compute roles involved in the incident. 

**Cryptographic Erase**
Following guidance from [NIST SP 800-88 Rev. 1](https://doi.org/10.6028/NIST.SP.800-88r1) cryptographic erase is the recommend solution to ensuring sanitization of spilled data in cloud environments. 

Cryptographic Erase (CE) leverages the encryption of target data by enabling sanitization of the target data’s encryption key. This leaves only the ciphertext remaining on the media, effectively sanitizing the data by preventing read-access.

Without the encryption key used to encrypt the target data, the data is unrecoverable. The level of effort needed to decrypt this information without the encryption key then is the lesser of the NIST SP 800-88 Rev. 1 Guidelines for Media Sanitization strength of the cryptographic key or the strength of the cryptographic algorithm and mode of operation used to encrypt the data.

If strong cryptography is used, sanitization of the target data is reduced to sanitization of the encryption key(s) used to encrypt the target data. Thus, with CE, sanitization may be performed with high assurance much faster than with other sanitization techniques. The encryption itself acts to sanitize the data, subject to constraints identified in this guidelines document. Federal agencies must use FIPS 140 validated encryption modules12 in order to have assurance that the conditions stated above have been verified for the SED.

AWS Key Management Service (KMS) can be used to generate cryptographic keys to perform cryptographic erase within AWS environments. 

**Prepare for cryptographic erase:**

1. Generate a new Customer Managed Key (CMK) with a strict key policy to be used in Cryptographic Erase (CE) operations. Limit key access to responders only. Please record the newly created keyid/key ARN for use in later operations: 

```
aws kms create-key --tags TagKey=Owner,TagValue=SecurityResponders --description "Key used to perform cryptographic erase operations" --policy file://keypolicy.json --region us-gov-west-1

keypolicy.json:
{
   "Statement": [
      {
         "Effect": "Deny",
         "Principal": "*",
         "Action": "kms:*",
         "Resource": "*",
         "Condition": {
            "StringNotEquals": {
                "aws:PrincipalArn": [
                    "arn:aws:iam::123456789012:role/example-responder-role-name",
                    "arn:aws:iam::123456789012:user/example-responder-user-name",
                    "arn:aws:sts::123456789012:federated-user/example-responder-user-name",
                    "arn:aws:sts::123456789012:assumed-role/example-responder-role/*"                ]

            }
         }
      },
      {
         "Effect": "Allow",
         "Principal": [
           "arn:aws:iam::123456789012:role/example-responder-role-name",
           "arn:aws:iam::123456789012:user/example-responder-user-name",
           "arn:aws:sts::123456789012:federated-user/example-responder-user-name",
           "arn:aws:sts::123456789012:assumed-role/example-responder-role/*"         ],
         "Action": "kms:*",
         "Resource": "*"
      }
   ]
}
```

**S3**

If the data spill occurs in S3, follow these steps to contain the incident:

1. Quickly restrict access to the S3 bucket to responder roles only to ensure that data does not spill further. If you are using an identity other than the root user of the Amazon Web Services account that owns the bucket, the calling identity must have the `PutBucketPolicy` permissions on the specified bucket and belong to the bucket owner's account in order to use this operation. Please note, as a security precaution, the root user of the Amazon Web Services account that owns a bucket can always use this operation, even if the policy explicitly denies the root user the ability to perform this action. GovCloud accounts do not have root users. 

    1. Apply a strict bucket policy, limiting access to responder roles only. ADC users, please ensure that you adjust your ARN's to reflect your specific partition. Example `arn:aws-us-gov:` 
    
```
aws s3api put-bucket-policy --bucket MyBucket --policy file://policy.json --region us-gov-west-1

policy.json:
{
   "Statement": [
      {
         "Effect": "Deny",
         "Principal": "*",
         "Action": "s3:*",
         "Resource": [
            "arn:aws:s3:::MyBucket",
            "arn:aws:s3:::MyBucket/*"
         ], 
         "Condition": {
            "StringNotEquals": {
                "aws:PrincipalArn": [
                    "arn:aws:iam::123456789012:role/example-responder-role-name",
                    "arn:aws:iam::123456789012:user/example-responder-user-name",
                    "arn:aws:sts::123456789012:federated-user/example-responder-user-name",
                    "arn:aws:sts::123456789012:assumed-role/example-responder-role/*",
                    "arn:aws:iam::123456789012:root" #example responder account
                ]

            }
         }
      }
   ]
}

```

2. Once this strict bucket policy is in place, perform cryptographic erase on the spilled objects in the bucket: 

`aws s3 cp s3://awsexamplebucket/myfile s3://awsexamplebucket/myfile --sse aws:kms --sse-kms-key-id arn:aws:kms:us-west-2:111122223333:key/3aefc301-b7d2-4601-9298-5a854cf9999d` 

3. Delete the newly re-encrypted object: 

`aws s3api delete-object --bucket my-bucket --key test.txt` 

**EC2**

If the DataSpill occurs in EC2 follow these steps to contain the incident: 

1. Isolate the instance from all network communications besides the minimum necessary for responders to access the instance by applying a strict security group to the instance.

2. Within the operating system, securely overwrite the spilled object on the file system in accordance with your organization's policy. EBS volumes are block level storage devices and such, customers are able to interact directly at the block level, and overwrite drive space directly to ensure that data is irrecoverable on a drive. 

* An example for Linux operating systems would be using the Shred utility to overwrite the object on disk multiple times: 

`shred -vfz -n 7 classified.txt` 

* An example for Windows operating systems would be using the Systems Internals tool SDelete to overwrite the object on disk multiple times: 

`sdelete [-p passes] [-z|-c] <physical disk number>` 

3. Restore the image from a previous snapshot
    1. If the data spill occurred on a root volume, stop the affected instance
    2. Detach the volume from the EC2 instance
    3. Create a volume from a previously created snapshot validated to have been made before the data spill occurred 
    4. Attach the newly created volume to the EC2 instance
    5. Delete the volume that the data spill occurred on

Upon deletion of an EBS volume, AWS wipes the volume to ensure that data is not recoverable. *To learn more about EBS security, and how volumes are wiped upon deletion, please see the following resources*: 

[Security Compute Services Whitepaper](https://d0.awsstatic.com/whitepapers/Security/Security_Compute_Services_Whitepaper.pdf)

https://us-east-1.console.aws.amazon.com/artifact/reports/aws - review the associated authorization and attestation packages relevant to 

### Part 3: Complete Cryptographic Erase

  1. Schedule the deletion of the CE KMS key to complete a CE. By default, KMS applies a waiting period of 30 days, but you can specify a waiting period of 7-30 days. When this operation is successful, the key state of the KMS key changes to PendingDeletion and the key can't be used in any cryptographic operations. It remains in this state for the duration of the waiting period. Before the waiting period ends, you can use CancelKeyDeletion to cancel the deletion of the KMS key. After the waiting period ends, KMS deletes the KMS key, its key material, and all KMS data associated with it, including all aliases that refer to it.

  `aws kms schedule-key-deletion --key-id arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab --pending-window-in-days 7` 

### Part 4: Recover from the Incident

1. Restore connectivity/access to the affected resources. 
- Review and then apply operational resource policies
- Review and then apply encryption configurations using operational KMS keys
- Review and then apply operational security groups. 

2. Restore permissions to principals in the environment. 
- Remove users from DenyAll groups and Permission Sets. 
- Remove DenyAll policies from compute roles and restore them to original permissions. 

### Part 5: Post-Incident Activity

This activity contains two parts. Firstly, some compromised resources may require forensic analysis, either to fulfil regulatory obligations or improved incident handling, both taking input from the root cause analysis that will result from forensic investigation. The second part is a “sharpen the saw” activity which helps teams to assess their response to the actual incident, determine what worked and what didn’t, update the process based on that information and record these findings.

Firstly, perform any required forensic investigation to determine (for affected resources) to determine that classified data was successfully removed from the environment. 

1. Seek organizational guidance on specific review required for the level of classified data involved in the spill. 

Secondly, review the incident itself and the response to it, to determine if anything needs to be changed for handling any similar incidents in the future.

1. Review the incident handling and the incident handling process with key stakeholders identified in Part 1, Step 8.
2. Document lessons learned, including attack vector(s) mitigation(s), misconfiguration, etc.
3. Store the artifacts from this process with the application information in the CMDB entry for the application and also in the CMDB entry for the credential compromise response process.
