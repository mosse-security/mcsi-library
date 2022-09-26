:orphan:
(azure-sentinel-comprehensive-security-management-for-the-azure-cloud-platform)=
# Azure Sentinel: Comprehensive Security Management for the Azure Cloud Platform
  

Azure Sentinel is a system that runs on the Azure cloud platform used for security and information management. It combines threat detection with the ability to see potential threats, which it employs to give a threat response. It’s a comprehensive security management system. It also gives users information about their systems' health, finds vulnerabilities, and prevents harmful software from running. Essential components of Azure Sentinel are patch management, vulnerability scanning, endpoint monitoring, performance analysis, and configuration consolidation.

## Sentinel works by using four functions 

### Data Collection
   
Collect data on a large scale across all customers' devices, services, and facilities, wherever it resides on-premises or in the cloud

### Detection

Using threat intelligence Azure sentinel can detect previously unknown attacks and reduce false positives with Microsoft's unrivalled analytics.

### Investigation 

In Azure Sentinel you can investigate using one of four methods: correlation, trend, alarm, and behaviour analytics.

- Correlation examines data to determine if there are any links between incidents. Sentinel can utilize correlation to see whether the data shows any tendencies that could indicate a vulnerability.
  
- Azure Sentinel uses ``trend" in data to discern changes over time. 
  
- Azure Sentinel can trigger alerts based on predefined rules which it uses to send notifications to selected individuals
  
- Sentinel uses behaviour analytics as a crucial element because it can provide insights for better decision making. It entails recognizing problematic user behaviour, detecting trends in user activity, and tracking changes in user behaviour over time. Sentinel increases system performance and data security by gathering reliable data.

### Response

Sentinel's built-in synchronisation and automation of typical processes make it easy for organisations to respond to events quickly.


## Advantages of adopting Azure Sentinel 

 - Benefits include Improved security, faster reaction times, and cost reduction.

-  With Azure AI on your side, sentinel improves threat protection.

-  It provides enterprise-wide security.

-  Each Sentinel toolkit saves time and enables employees to make the most of their time at work.

-  Azure Sentinel's interactive dashboard allows decision-makers to see data from across the organisation in real-time.


## Getting Started with Azure Sentinel 

### Acquire access (credentials) to Azure Sentinel

1. Create an azure free account 

2. In the Azure portal, look for Azure Sentinel and add it to the platform.

3. Create log analytics(This is the workspace where log data are stored ) https://docs.microsoft.com/azure/log-analytics/log-analytics-quick-create-workspace

*- Permissions to contribute to the subscription in which the Azure Sentinel workspace is hosted.*
*- Authorizations to contribute or read are needed to the shared folder where the workspace is.*
*- To link data sources, further permissions may be required.*

### Connect Data Source

Connectors in Azure Sentinel provide real-time connectivity with a variety of industrial solutions. Using built-in connectors, you can also collect data from current security solutions such as endpoint security. You can also connect any compatible data sources to Azure Sentinel using API or event log and file systems.

Use your account credentials to log in to Azure.

1. Go to Azure Sentinel and click on it.
   
2. Select Data Connectors from the drop-down menu.
   
3. Select the data source you want to link by clicking on its row.
   
4. To examine the configuration steps for connecting the data source, go to the Open connector page.
   
5. After you've connected your data sources, your data begins to trickle into Azure Sentinel and is available for you to use.

*If you want to learn more about data connections, go to 
https://docs.microsoft.com/azure/sentinel/connect-data-sources*

### Gain visibility across the organisation by using the comprehensive dashboard and workbooks

Workbooks can be used to view data, or you can develop a new dashboard from start or based on an older one. These are built on Azure Monitor Workbooks, which allow you to create sophisticated, interactive reports based on the data you have collected.
 
- **Commence with the Summary dashboard:** which provides a quick snapshot of your workspace's security posture.

- **Timeline of events and alerts:** Monitor the list of events that occurred and how many alerts were generated because of those occurrences.

- **Untrusted events:** Users can get notified when traffic from known malicious sources is discovered.

- **Incidents:** View your most recent attacks, as well as the intensity and number of notifications linked to each one.

- **Anomalies in data sources:** Analyse various data sources for anomalies using models established by Microsoft's experts.

To create interactive dashboards for specific data sources, another option is to use the built-in workbook templates. You can utilise built-in templates to get more visibility on specific data sources. These workbooks give descriptive information

- Select Workbooks from the Threat management option in Azure Sentinel.
- The built-in dashboard templates are located under the Templates tab.
- To see the template, select the row for the template source you want to see, ensure you have the correct data types, and then click View workbook.
- Go to the My Workbooks page to see all the workbooks that you've saved or created.

:::{seealso}
Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)
:::