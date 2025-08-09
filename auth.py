"""
Authentication module for Azure/Microsoft Graph API access.
"""

import os
import sys
import getpass
import logging
from typing import Optional, Tuple, Any
from roadtools.roadlib.auth import Authentication, AuthenticationException
from roadtools.roadlib.deviceauth import DeviceAuthentication
from roadtools.roadtx.selenium import SeleniumAuthentication
from roadtools.roadtx.utils import find_redirurl_for_client
import codecs
import json


def get_token_non_interactive(username: str, password: Optional[str], resource: str, client: str, tenant: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Authenticate using username/password non-interactively.
    
    Args:
        username: Username for authentication
        password: Password for authentication  
        resource: Azure resource URL
        client: Client application ID
        tenant: Tenant ID
        
    Returns:
        Tuple of (access_token, refresh_token) or (None, None) on failure
    """
    if not username:
        logging.error('No username supplied!')
        return None, None

    if username and not password:
        password = getpass.getpass(prompt="Password: ")

    try:
        auth = Authentication()
        auth.username = username
        auth.password = password
        auth.tenant = tenant
        auth.set_client_id(client)
        auth.set_resource_uri(resource)

        res = auth.authenticate_username_password_native()
        save_tokens(auth)
        return res.get('accessToken'), res.get('refreshToken')
    except AuthenticationException as e:
        logging.error(f"Authentication failed: {e}")
        return None, None
    except Exception as e:
        logging.error(f"Unexpected error during authentication: {e}")
        return None, None

def save_tokens(auth: Authentication)->None:
    with codecs.open('.roadtools_auth', 'w', 'utf-8') as outfile:
        json.dump(auth.tokendata, outfile)
        # print('Tokens were written to {}'.format('.roadtools_auth'))

def load_tokens() -> Tuple[Optional[str], Optional[str]]:
    """
    Load authentication tokens from .roadtools_auth file.
    
    Returns:
        Tuple of (access_token, refresh_token) or (None, None) if file doesn't exist
        or tokens are not present
    """
    try:
        with codecs.open('.roadtools_auth', 'r', 'utf-8') as infile:
            token_data = json.load(infile)
            return token_data.get('accessToken'), token_data.get('refreshToken')
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        logging.error(f"Failed to load tokens: {e}")
        return None, None

def get_token_interactive(username: Optional[str], password: Optional[str], resource: str, client: str, tenant: Optional[str], verbose: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """
    Authenticate using interactive browser-based flow.
    
    Args:
        username: Username for authentication
        password: Password for authentication
        resource: Azure resource URL
        client: Client application ID
        tenant: Tenant ID
        verbose: Whether to show verbose output
        
    Returns:
        Tuple of (access_token, refresh_token) or (None, None) on failure
    """
    try:
        auth = Authentication()
        auth.username = username
        auth.password = password
        auth.tenant = tenant
        auth.set_client_id(client)
        auth.set_resource_uri(resource)

        # Interactive auth is really noisy, suppress output unless verbose
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        if not verbose:
            sys.stderr = open(os.devnull, 'w')    
            sys.stdout = open(os.devnull, 'w')

        deviceauth = DeviceAuthentication(auth)
        redirect_url = find_redirurl_for_client(auth.client_id, interactive=False)
        selauth = SeleniumAuthentication(auth, deviceauth, redirect_url)

        url = auth.build_auth_url(redirect_url, 'code', None)
        service = selauth.get_service(None)
        if not service:
            return None, None
        selauth.driver = selauth.get_webdriver(service, intercept=True)
            
        result = selauth.selenium_login_regular(url, username, password)

        sys.stdout = original_stdout
        sys.stderr = original_stderr

        save_tokens(auth)

        return result.get('accessToken'), result.get('refreshToken')
    except Exception as e:
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        logging.error(f"Interactive authentication failed: {e}")
        return None, None


def get_token_from_refresh(refresh_token: str, resource: str, client: str, tenant: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Get new access token using refresh token.
    
    Args:
        refresh_token: Refresh token
        resource: Azure resource URL
        client: Client application ID
        tenant: Tenant ID
        
    Returns:
        Tuple of (access_token, refresh_token) or (None, None) on failure
    """
    try:
        auth = Authentication()
        auth.tenant = tenant
        auth.set_client_id(client)
        auth.set_resource_uri(resource)

        if refresh_token == "file":
            _, refresh_token = load_tokens()
            if not refresh_token:
                logging.error("Failed to load refresh token from file.")
                return None, None

        resp = auth.authenticate_with_refresh_native(refresh_token, client_secret=None)
        save_tokens(auth)
        return resp.get('accessToken'), resp.get('refreshToken')
    except AuthenticationException as e:
        logging.error(f"Token refresh failed: {e}")
        return None, None
    except Exception as e:
        logging.error(f"Unexpected error during token refresh: {e}")
        return None, None


def get_token(args: Any, resource: str, client: str, tenant: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Get authentication token based on provided arguments.
    
    Args:
        args: Command line arguments namespace
        resource: Azure resource URL
        client: Client application ID
        tenant: Tenant ID
        
    Returns:
        Tuple of (access_token, refresh_token) or (None, None) on failure
    """
    if args.refresh_token:
        access_token, refresh_token = get_token_from_refresh(args.refresh_token, resource, client, tenant)
    elif args.interactive:
        access_token, refresh_token = get_token_interactive(args.username, args.password, resource, client, tenant)
    else:
        access_token, refresh_token = get_token_non_interactive(args.username, args.password, resource, client, tenant)
    
    return access_token, refresh_token
