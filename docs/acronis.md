## About the connector
Acronis Cyber Protect Connect is a remote access solution to remotely manage workloads — quickly and easily. This connector facilitates automated operations to fetch alerts, target, service etc.
<p>This document provides information about the Acronis Cyber Protect Cloud Connector, which facilitates automated interactions, with a Acronis Cyber Protect Cloud server using FortiSOAR&trade; playbooks. Add the Acronis Cyber Protect Cloud Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with Acronis Cyber Protect Cloud.</p>

### Version information

Connector Version: 1.0.0

FortiSOAR&trade; Version Tested on: 7.6.1-351

Authored By: Fortinet

Certified: No
## Installing the connector
<p>Use the <strong>Content Hub</strong> to install the connector. For the detailed procedure to install a connector, click <a href="https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector" target="_top">here</a>.</p><p>You can also use the <code>yum</code> command as a root user to install the connector:</p>
<pre>yum install cyops-connector-acronis</pre>

## Prerequisites to configuring the connector
- You must have the credentials of Acronis Cyber Protect Cloud server to which you will connect and perform automated operations.
- The FortiSOAR&trade; server should have outbound connectivity to port 443 on the Acronis Cyber Protect Cloud server.

## Minimum Permissions Required
- Not applicable

## Configuring the connector
For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector)
### Configuration parameters
<p>In FortiSOAR&trade;, on the Connectors page, click the <strong>Acronis Cyber Protect Cloud</strong> connector row (if you are in the <strong>Grid</strong> view on the Connectors page) and in the <strong>Configurations</strong> tab enter the required configuration details:</p>
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Server URL</td><td>Service based URI to which you will connect and perform the automated operations.
</td>
</tr><tr><td>Client ID</td><td>Client ID configured for your account for using the Acronis.
</td>
</tr><tr><td>Client Secret</td><td>Client Secret configured for your account for using the Acronis.
</td>
</tr><tr><td>Verify SSL</td><td>Specifies whether the SSL certificate for the server is to be verified or not. <br/>By default, this option is set to True.</td></tr>
</tbody></table>

## Actions supported by the connector
The following automated operations can be included in playbooks and you can also use the annotations to access operations:
<table border=1><thead><tr><th>Function</th><th>Description</th><th>Annotation and Category</th></tr></thead><tbody><tr><td>Create an Alert</td><td>Creates and activates an alert based on the type, category and other parameters you have specified.</td><td>create_alert <br/>Investigation</td></tr>
<tr><td>Get Alerts</td><td>Retrieves the alert/alerts based on the alerts ID parameter you have specified.</td><td>get_alerts <br/>Investigation</td></tr>
<tr><td>Get Alert Types</td><td>Retrieves all registered alert types based on the OS type, category, order parameter you have specified.</td><td>get_alert_types <br/>Investigation</td></tr>
<tr><td>Delete an Alert</td><td>Deletes an alert based on the Alert ID parameter you have specified.</td><td>delete_alert <br/>Investigation</td></tr>
<tr><td>Get Categories</td><td>Retrieves the available categories from Acronis.</td><td>get_categories <br/>Investigation</td></tr>
</tbody></table>

### operation: Create an Alert
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Title</td><td>(Optional) Specify the title to create an alert in Acronis.
</td></tr><tr><td>Type</td><td>(Optional) Specify the type to create an alert in Acronis.
</td></tr><tr><td>Category</td><td>(Optional) Select the category to create an alert in Acronis. you can choose from Backup, System, Licensing, Disaster recovery, Antimalware protection, URL filtering, Management, Monitoring, Device control, Email security, EDR, Public clouds connection, Performance logging and Device discovery
</td></tr><tr><td>Tenant</td><td>(Optional) Specify the tenant details to create an alert in Acronis.
</td></tr><tr><td>Description</td><td>(Optional) Specify the description to create an alert in Acronis.
</td></tr><tr><td>Other Fields</td><td>(Optional) Specify the other fields to create an alert in Acronis.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "id": ""
}</pre>
### operation: Get Alerts
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Alert ID</td><td>(Optional) Specify the alert ID to retrieve from Acronis. e.g. E5FA7823-74F5-549A-9C1A-BAA020062DCA
</td></tr><tr><td>Limit</td><td>(Optional) Specify the maximum number of records that this operation should return.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "items": [
        {
            "id": "",
            "type": "",
            "details": {
                "resourceId": "",
                "resourceName": "",
                "serviceName": ""
            },
            "createdAt": "",
            "severity": "",
            "affinity": "",
            "receivedAt": "",
            "updatedAt": "",
            "tenant": {
                "id": "",
                "uuid": "",
                "locator": ""
            },
            "category": ""
        }
    ],
    "paging": {
        "cursors": {}
    }
}</pre>
### operation: Get Alert Types
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>OS Type</td><td>(Optional) Select the OS type to retrieve the list of alerts types. you can choose from ios, linux, macos and windows
</td></tr><tr><td>Category</td><td>(Optional) Select the category to retrieve the list of alerts types. you can choose from Backup, System, Licensing, Disaster recovery, Antimalware protection, URL filtering, Management, Monitoring, Device control, Email security, EDR, Public clouds connection, Performance logging and Device discovery
</td></tr><tr><td>Order</td><td>(Optional) Select the order to retrieve the list of alerts types. you can choose from asc and desc
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.
### operation: Delete an Alert
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Alert ID</td><td>Specify the alert ID to delete. e.g. a21dcdb2-bf37-39dB-9Ce0-de11A4Bf3EeD
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.
### operation: Get Categories
#### Input parameters
None.
#### Output
The output contains the following populated JSON schema:

<pre>{
    "items": [
        {
            "name": ""
        }
    ]
}</pre>
## Included playbooks
The `Sample - acronis - 1.0.0` playbook collection comes bundled with the Acronis Cyber Protect Cloud connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR&trade; after importing the Acronis Cyber Protect Cloud connector.

- Create an Alert
- Delete an Alert
- Get Alert Types
- Get Alerts
- Get Categories

**Note**: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection since the sample playbook collection gets deleted during connector upgrade and delete.
