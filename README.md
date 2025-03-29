# Azure Security Benchmark Report (MSBReport)

## Overview

MSBReport is a Streamlit-based web application for analyzing and visualizing security recommendations for Azure resources based on Microsoft Security Benchmark standards. The tool helps security professionals and administrators identify vulnerabilities and maintain compliance with best practices.
![image](https://github.com/user-attachments/assets/023f4e41-0dd8-4341-9692-b140add277e3)


## Features

- **Azure Integration**: Connect directly to your Azure environment using secure authentication
- **Subscription Analysis**: Select and analyze specific Azure subscriptions
- **Security Assessment**: View comprehensive security recommendations and compliance status
- **Visualization**: Interactive dashboards with metrics and visual indicators
- **Categorization**: Group findings by security categories (Identity & Access, Networking, etc.)
- **Export Options**: Save reports in various formats for documentation or further analysis
- **Modern Interface**: Clean, user-friendly design based on Microsoft's Fluent UI principles

## Installation

### Requirements

- Python 3.7+
- Azure subscription
- App Registration with appropriate permissions

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/MSBReport.git
   cd MSBReport
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure authentication:
   - Create a `.env` file with your Azure credentials:
     ```
     TENANT_ID=your_tenant_id
     CLIENT_ID=your_client_id
     CLIENT_SECRET=your_client_secret
     ```

## Azure Configuration

1. Create an App Registration in Azure AD:
   - Navigate to Azure Active Directory > App registrations > New registration
   - Provide a name and configure the redirect URI as appropriate
   - Note the Application (client) ID and Directory (tenant) ID

2. Create a client secret:
   - In your App Registration, go to Certificates & secrets
   - Add a new client secret and note its value

3. Assign necessary permissions:
   - Microsoft Graph API: `Directory.Read.All`
   - Azure Service Management API: `user_impersonation`
   - Grant admin consent for these permissions

## Usage

1. Start the application:
   ```bash
   streamlit run app.py
   ```

2. If you've set up the `.env` file correctly, the application will attempt automatic login

3. Select your Azure subscription from the dropdown menu

4. Click "Generate report" to analyze security recommendations

5. Explore the interactive dashboard with:
   - Overall compliance score
   - Recommendations by severity
   - Detailed findings organized by category
   - Actionable remediation steps

## Technical Details

### API Usage

The application uses Azure APIs to retrieve security assessments:

- **Azure Resource Graph**: For querying security recommendations across resources
- **Azure Management API**: For subscription and resource management
- **Microsoft Graph API**: For identity and access information

### Authentication Flow

The application uses OAuth 2.0 client credentials flow for service-to-service authentication:

```python
def get_access_token(tenant_id, client_id, client_secret):
    """Gets access token using App Registration credentials"""
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    scope = "https://management.azure.com/.default"
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': scope
    }
```

### Resource Graph Queries

The application uses Azure Resource Graph to efficiently query security assessments across subscriptions:

```python
def get_security_assessments(access_token, subscription_id, debug=False):
    """Get security assessments for a given subscription using Azure Resource Graph."""
    url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
    
    query = """
    securityresources
    | where type == 'microsoft.security/assessments' 
    | where subscriptionId == "{subscription_id}"
    | extend resourceId=id, 
        recommendationId=name, 
        recommendationName=properties.displayName, 
        source=properties.resourceDetails.Source, 
        recommendationState=properties.status.code, 
        description=properties.metadata.description, 
        remediationDescription=properties.metadata.remediationDescription, 
        recommendationSeverity=properties.metadata.severity, 
        category=properties.metadata.categories
    | project subscriptionId, resourceId, recommendationId, recommendationName, source, 
        recommendationState, description, remediationDescription, recommendationSeverity, 
        category, properties
    """
    
    
```
