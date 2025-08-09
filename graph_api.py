"""
Microsoft Graph API module for user invitations and directory object lookups.
"""

import requests
import logging
from typing import Optional, List, Dict, Any
import config as cfg


def invite_user(token: str, email: str) -> Optional[Dict[str, Any]]:
    """
    Invite a user to the current Azure AD tenant.
    
    Args:
        token: Graph API access token
        email: Email address of user to invite
        
    Returns:
        Invitation response dict or None on failure
    """
    url = f"{cfg.GRAPH_RESOURCE}{cfg.GRAPH_API_VERSION}/invitations"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {
        "invitedUserEmailAddress": email,
        "inviteRedirectUrl": cfg.DEFAULT_INVITE_REDIRECT_URL,
        "sendInvitationMessage": False
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to invite user {email}: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return None


def lookup_principal_ids(token: str, tenant: str, pids: List[str]) -> Dict[str, Any]:
    """
    Look up principal IDs to get user/service principal details.
    
    Args:
        token: Graph API access token
        tenant: Tenant ID
        pids: List of principal IDs to look up
        
    Returns:
        Lookup results dict or empty dict on failure
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    url = f'{cfg.GRAPH_RESOURCE}{cfg.GRAPH_API_VERSION}/directoryObjects/getByIds'

    try:
        payload = {
            "ids": pids,
            "types": [
                "user",
                "group",
                "servicePrincipal",
                "device",
                "directoryObjectPartnerReference"
            ]
        }
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_msg = f'Principal lookup failed: {e}'
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return {}
    except Exception as e:
        logging.error(f'Unexpected error during principal lookup: {e}')
        return {}


def get_current_user(token: str) -> Optional[Dict[str, Any]]:
    """
    Get the current authenticated user's information.
    
    Args:
        token: Graph API access token
        
    Returns:
        User information dict or None on failure
    """
    url = f"{cfg.GRAPH_RESOURCE}{cfg.GRAPH_API_VERSION}/me"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to get current user: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return None


def get_external_collaboration_settings(token: str) -> Optional[Dict[str, Any]]:
    """
    Get external collaboration settings from Azure AD policies.
    
    Args:
        token: Graph API access token
        
    Returns:
        External collaboration settings dict or None on failure
    """
    url = f"{cfg.GRAPH_RESOURCE}{cfg.GRAPH_API_BETA_VERSION}/policies/authorizationPolicy/authorizationPolicy"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to get external collaboration settings: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return None
