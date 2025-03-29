import requests
import json
from typing import Dict, List, Optional, Any


def get_subscriptions(access_token: str) -> List[Dict[str, Any]]:
    """
    Get a list of available Azure subscriptions.
    
    Args:
        access_token: API access token
        
    Returns:
        List of subscriptions or empty list in case of error
    """
    url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json().get('value', [])
    except requests.exceptions.RequestException as e:
        print(f"Error while retrieving subscriptions: {e}")
        return []


def get_security_assessments(access_token: str, subscription_id: str, debug: bool = False) -> List[Dict[str, Any]]:
    """
    Get security assessments for a given subscription
    using Azure Resource Graph.
    
    Args:
        access_token: API access token
        subscription_id: Azure subscription ID
        debug: Whether to display debug information
        
    Returns:
        List of security assessments or empty list in case of error
    """
    url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    # Kusto (KQL) query for Azure Resource Graph
    query = f"""
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
    | project subscriptionId, resourceId, recommendationId, recommendationName, source, recommendationState, description, remediationDescription, recommendationSeverity, category, properties
    """
    
    payload = {
        "subscriptions": [subscription_id],
        "query": query,
        "options": {
            "resultFormat": "objectArray"
        }
    }
    
    try:
        if debug:
            print(f"Sending Resource Graph query: {json.dumps(payload, indent=2)}")
        
        response = requests.post(url, headers=headers, json=payload)
        
        if debug:
            print(f"Response status: {response.status_code}")
            print(f"Response headers: {response.headers}")
        
        response.raise_for_status()
        
        result = response.json()
        
        if debug:
            print(f"Received {len(result.get('data', []))} results")
            if len(result.get('data', [])) > 0:
                print("Sample result:")
                print(json.dumps(result['data'][0], indent=2))
        
        return result.get('data', [])
    except requests.exceptions.RequestException as e:
        print(f"Error while retrieving security assessments: {e}")
        if hasattr(e, 'response') and e.response:
            print(f"API Response: {e.response.text}")
        return []


def get_assessment_details(access_token: str, assessment_id: str, debug: bool = False) -> Dict[str, Any]:
    """
    Get details for a specific security assessment.
    
    Args:
        access_token: API access token
        assessment_id: Full security assessment ID
        debug: Whether to display debug information
        
    Returns:
        Security assessment details or empty dict in case of error
    """
    url = f"https://management.azure.com{assessment_id}?api-version=2020-01-01"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        if debug:
            print(f"Retrieving assessment details: {assessment_id}")
            
        response = requests.get(url, headers=headers)
        
        if debug:
            print(f"Response status: {response.status_code}")
        
        response.raise_for_status()
        result = response.json()
        
        if debug:
            print("Received data:")
            print(json.dumps(result, indent=2))
            
        return result
    except requests.exceptions.RequestException as e:
        print(f"Error while retrieving assessment details: {e}")
        if hasattr(e, 'response') and e.response:
            print(f"API Response: {e.response.text}")
        return {}


def get_security_benchmarks_list(access_token: str, subscription_id: str, debug: bool = False) -> List[Dict[str, Any]]:
    """
    Get list of available Microsoft Security Benchmark versions for a subscription.
    
    Args:
        access_token: API access token
        subscription_id: Azure subscription ID
        debug: Whether to display debug information
        
    Returns:
        List of security benchmark versions
    """
    url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    # Query to get list of benchmarks
    query = f"""
    securityresources
    | where type == "microsoft.security/securescores"
    | where subscriptionId == "{subscription_id}" 
    | project id, name, displayName=properties.displayName, properties
    """
    
    payload = {
        "subscriptions": [subscription_id],
        "query": query,
        "options": {
            "resultFormat": "objectArray"
        }
    }
    
    try:
        if debug:
            print(f"Sending benchmarks query: {json.dumps(payload, indent=2)}")
            
        response = requests.post(url, headers=headers, json=payload)
        
        if debug:
            print(f"Response status: {response.status_code}")
        
        response.raise_for_status()
        
        result = response.json()
        
        if debug:
            print(f"Received {len(result.get('data', []))} benchmarks")
            if len(result.get('data', [])) > 0:
                print("Sample benchmark:")
                print(json.dumps(result['data'][0], indent=2))
                
        return result.get('data', [])
    except requests.exceptions.RequestException as e:
        print(f"Error while retrieving benchmark list: {e}")
        if hasattr(e, 'response') and e.response:
            print(f"API Response: {e.response.text}")
        return []


def debug_assessment_structure(access_token: str, subscription_id: str) -> None:
    """
    Helper function to analyze security assessment structure.
    Displays all available fields and their structure.
    
    Args:
        access_token: API access token
        subscription_id: Azure subscription ID
    """
    url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    # Query retrieving full recommendation structure
    query = f"""
    securityresources
    | where type == 'microsoft.security/assessments' 
    | where subscriptionId == "{subscription_id}"
    | limit 5
    """
    
    payload = {
        "subscriptions": [subscription_id],
        "query": query,
        "options": {
            "resultFormat": "objectArray"
        }
    }
    
    try:
        print("Analyzing security assessment structure...")
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        
        result = response.json()
        assessments = result.get('data', [])
        
        if not assessments:
            print("No security assessments found.")
            return
            
        print(f"Found {len(assessments)} security assessments.")
        print("Details of first assessment:")
        print(json.dumps(assessments[0], indent=2))
        
        # Analysis of available fields
        print("\nAvailable fields in security assessment:")
        for key in assessments[0].keys():
            print(f"- {key}")
            
        # Analysis of properties structure
        if 'properties' in assessments[0]:
            print("\nStructure of 'properties' field:")
            for key in assessments[0]['properties'].keys():
                print(f"- properties.{key}")
                
            # Check if fields related to Microsoft Security Benchmark exist
            props = assessments[0]['properties']
            print("\nFields that may contain Microsoft Security Benchmark information:")
            
            if 'displayName' in props:
                print(f"- properties.displayName: {props['displayName']}")
                
            if 'description' in props:
                print(f"- properties.description: {props['description'][:100]}...")
                
            if 'metadata' in props and isinstance(props['metadata'], dict):
                print("\nMetadata contents:")
                for meta_key, meta_value in props['metadata'].items():
                    if isinstance(meta_value, (str, int, bool, float)):
                        print(f"- properties.metadata.{meta_key}: {meta_value}")
                    else:
                        print(f"- properties.metadata.{meta_key}: {type(meta_value)}")
                        
    except requests.exceptions.RequestException as e:
        print(f"Error during assessment structure analysis: {e}")
        if hasattr(e, 'response') and e.response:
            print(f"API Response: {e.response.text}")
