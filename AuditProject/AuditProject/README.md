# Distributed Audit
> This is a distributed audit architecture for workflows.

[![license](https://img.shields.io/badge/license-ASF2-blue.svg)](https://github.com/antonionehme/repo/blob/master/AuditProject/AuditProject/LICENSE)

AuditProject is a proof of concept for a distributed architecture designed for collaborative generation of workflow audit trails. We simulate a linear topology in which participants exchange messages, report encrypted audit records, and cooperate to construct audit trails.

## Start the Audit Server
This is a Spring-boot-Application. You can test it by executing the maven wrapper to create the jar files.

```shell
cd AuditProject
./mvnw package
```
Three types of modules are part of this project:
* __common__: contains the common classes shared among modules
* __node__: is the special node in charge of audit trail distribution, the audit server/
* __clients__: Each one is a participant in the workflow. They report audit records to the audit server, challenge the authenticity of each other's reported data and of the audit server.

Run the audit server. This would start the server on port 8080. Check <http://localhost:8080/address> and  <http://localhost:8080/transaction>  before you proceed to the next step.

## Run the workflow

WorkflowGenericParticipant.java combines all the functionalities and security checks of a workflow participant. Port numbers on which the participant run, participant's name, and the address to which it should sends a message to can be configured in the run configurationw with these arguments:
```shell
--a --port "8101" --name "Participant1" --recipientPort="8102"
```

Each participant should have certificate, and uses its public key to register with the audit server. The Audit server verifies each participant's certificate, and creates an address for each participant that is used to publish audit records. The audit server verifies the signature of each participant over the encrypted payload prior to listing the record on <http://localhost:8080/transaction>.


## Audit Trail Recursive Tracing
[Here](https://github.com/antonionehme/repo/blob/master/Audit-Trails-Decoding.pptx) is an explanation for the structure of our audit trail, and on how to recursively decode it and reproduce the exchanged message with a representation of the topology.

[![Audit Trails](https://github.com/antonionehme/repo/blob/master/ComplexWorkflow.jpg)](https://github.com/antonionehme/repo/blob/master/Audit-Trails-Decoding.pptx)