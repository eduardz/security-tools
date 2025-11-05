##### Architecture
 - Wazuh Server: The central component that receives, decodes, and analyzes logs from the agents.
 - Wazuh Agent: The client component installed on the monitored systems.
 - Wazuh Indexer: Indexes and stores the data for searching and analysis, often using the Elastic Stack's search engine.
 - Wazuh Dashboard: Provides a user interface for visualizing data, managing the system, and viewing alerts

##### Wazuh SIEM Capabilities

Wazuh can be used to monitor endpoints, cloud services and containers, and to aggregate and analyze data from external sources. Wazuh provides the following capabilities:
 - Security Analytics
 - Intrusion Detection
 - Log Data Analysis
 - File Integrity Monitoring
 - Vulnerability Detection
 - Configuration Assessment
 - Incident Response
 - Regulatory Compliance
 - Cloud Security Monitoring
 - Containers Security

##### Instalation
This is a working deployment (container deployment failed, broken installation for docker)

The oficial installation install script 
Deployed on Ubuntu 2024.04 LTS
```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a -o
```
