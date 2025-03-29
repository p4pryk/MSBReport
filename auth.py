import requests
import json
from typing import Dict, Optional


def get_access_token(tenant_id: str, client_id: str, client_secret: str) -> Optional[str]:
    """
    Gets access token using App Registration credentials.
    
    Args:
        tenant_id: Azure tenant ID
        client_id: Application ID (App Registration)
        client_secret: Application secret
        
    Returns:
        Access token or None in case of error
    """
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    
    # Scope for Microsoft Graph API and Azure Management API
    scope = "https://management.azure.com/.default"
    
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': scope
    }
    
    try:
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        
        token_data = response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            print("Error: No access token received")
            return None
            
        return access_token
    except requests.exceptions.RequestException as e:
        print(f"Error while retrieving token: {e}")
        return None
