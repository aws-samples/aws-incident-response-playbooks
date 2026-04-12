## AWS Incident Response Playbook Samples

These playbooks and ai-playbooks are created to be used as templates only. They should be customized by administrators working with AWS to suit their particular needs, risks, available tools and work processes. These guides are not official AWS documentation and are provided as-is to customers using AWS products and who are looking to improve their incident response capability.

The playbooks and ai-playbooks included cover several common scenarios faced by AWS customers. They outline steps based on the [NIST Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r3/final) (Special Publication 800-61 Revision 3) that can be used to:

* Gather evidence
* Contain and then eradicate the incident
* Recover from the incident
* Conduct post-incident activities, including post-mortem and feedback processes

The playbooks are markdown files designed to be used by humans as guidance when responding to an incident in their AWS environments. The ai-playbooks are designed to be consumed by an integrated development environment "IDE" leveraging a large language model "LLM" as "steering files" or "skills" (depending on your chosen IDE and LLM). Additional information for these files (including usage) are in the [README](aws-incident-response-playbooks/blob/main/ai-playbooks/README.md) in that directory.

Interested readers may also find the AWS Security Incident Response Guide (first published in June 2019) a useful guide as an overview of how the below steps were created.

Each playbook corresponds to a unique incident and there are 5 parts to handling each incident type, following the NIST guidelines referenced above. Each part corresponds to an action in that NIST document.

It is not sufficient to customize these scenarios to the need of your customers, organization or applications. It is important that these playbook scenarios are tested (for example, in Game Days) prior to deployment to your knowledge management system and that all responders are familiar with the actions required to respond to an incident.

Note that some of the incident response steps noted in each scenario may incur costs in your AWS account(s) for services used in either preparing for, or responding to incidents. Customizing these scenarios and testing them will help you to determine if additional costs will be incurred. You can use AWS Cost Explorer and look at costs incurred over a particular time frame (such as when running Game Days) to establish what the possible impact might be. Note also that if you have a subscription with an IDE or LLM, using the AI playbooks will also use tokens, contributing to whatever your token usage limitations are based on the plan(s) you have.

## Usage

The playbooks are written in markdown to facilitate editing and consumption into a variety of user systems.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License Summary

The documentation is made available under the Creative Commons Attribution-ShareAlike 4.0 International License. See the LICENSE file.

The sample code within this documentation is made available under the MIT-0 license. See the LICENSE-SAMPLECODE file.
