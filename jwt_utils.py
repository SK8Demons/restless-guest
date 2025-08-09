"""
JWT token inspection utilities for debugging Azure access tokens.
"""

import json
import base64
import logging
from typing import Dict, Any, Optional
from datetime import datetime


def decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode JWT token payload without signature verification.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded payload dict or None if decoding fails
    """
    try:
        # JWT tokens have 3 parts: header.payload.signature
        parts = token.split('.')
        if len(parts) != 3:
            logging.error("Invalid JWT token format - expected 3 parts separated by dots")
            return None
        
        # Decode the payload (second part)
        payload_part = parts[1]
        
        # Add padding if needed (JWT base64 encoding may not include padding)
        missing_padding = len(payload_part) % 4
        if missing_padding:
            payload_part += '=' * (4 - missing_padding)
        
        # Decode base64
        decoded_bytes = base64.urlsafe_b64decode(payload_part)
        payload = json.loads(decoded_bytes.decode('utf-8'))
        
        return payload
        
    except Exception as e:
        logging.error(f"Failed to decode JWT payload: {e}")
        return None


def format_timestamp(timestamp: int) -> str:
    """
    Convert Unix timestamp to human-readable format.
    
    Args:
        timestamp: Unix timestamp
        
    Returns:
        Formatted datetime string
    """
    try:
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return f"Invalid timestamp: {timestamp}"


def inspect_azure_token(token: str, verbose: bool = False, only_all_claims: bool = False) -> None:
    """
    Inspect and display information about an Azure access token.
    
    Args:
        token: Azure access token
        verbose: Whether to show verbose output
    """
    if not verbose:
        return

    payload = decode_jwt_payload(token)
    if not payload:
        print("❌ Failed to decode JWT token")
        return

    if only_all_claims:
        print("\n� ALL TOKEN CLAIMS:")
        print("-" * 40)
        for key, value in sorted(payload.items()):
            if key in ['iat', 'exp', 'nbf']:
                print(f"{key}: {value} ({format_timestamp(value)})")
            else:
                print(f"{key}: {value}")
        print("=" * 80)
        print()
        return

    print("\n" + "=" * 80)
    print("🔍 JWT TOKEN INSPECTION")
    print("=" * 80)

    # Display key token information
    print(f"🎯 Audience (aud): {payload.get('aud', 'Not specified')}")
    print(f"🏢 Issuer (iss): {payload.get('iss', 'Not specified')}")
    print(f"👤 Subject (sub): {payload.get('sub', 'Not specified')}")
    print(f"📧 Unique Name: {payload.get('unique_name', 'Not specified')}")
    print(f"🆔 Object ID (oid): {payload.get('oid', 'Not specified')}")
    print(f"🏠 Tenant ID (tid): {payload.get('tid', 'Not specified')}")
    print(f"📱 App ID (appid): {payload.get('appid', 'Not specified')}")
    print(f"🔐 App Display Name: {payload.get('app_displayname', 'Not specified')}")

    # Token timing information
    iat = payload.get('iat')
    exp = payload.get('exp')
    nbf = payload.get('nbf')

    if iat:
        print(f"📅 Issued At (iat): {format_timestamp(iat)}")
    if nbf:
        print(f"⏰ Not Before (nbf): {format_timestamp(nbf)}")
    if exp:
        print(f"⏳ Expires At (exp): {format_timestamp(exp)}")

        # Check if token is expired
        current_time = datetime.now().timestamp()
        if exp < current_time:
            print("⚠️  TOKEN IS EXPIRED!")
        else:
            time_left = exp - current_time
            minutes_left = int(time_left / 60)
            print(f"✅ Token valid for {minutes_left} more minutes")

    # Scopes and roles
    scp = payload.get('scp')
    roles = payload.get('roles', [])

    if scp:
        print(f"🔑 Scopes (scp): {scp}")
    if roles:
        print(f"👑 Roles: {', '.join(roles)}")

    # Authentication method info
    amr = payload.get('amr', [])
    if amr:
        print(f"🔒 Auth Methods (amr): {', '.join(amr)}")

    # Azure-specific claims
    ver = payload.get('ver')
    if ver:
        print(f"📋 Token Version: {ver}")

    # Show all claims if very verbose
    print("\n📋 ALL TOKEN CLAIMS:")
    print("-" * 40)
    for key, value in sorted(payload.items()):
        if key in ['iat', 'exp', 'nbf']:
            # Show timestamps in both formats
            print(f"{key}: {value} ({format_timestamp(value)})")
        else:
            print(f"{key}: {value}")

    print("=" * 80)
    print()


def inspect_token_scopes_for_resource_graph(token: str, verbose: bool = False) -> bool:
    """
    Check if the token has the necessary scopes for Resource Graph API.
    
    Args:
        token: Azure access token
        verbose: Whether to show verbose output
        
    Returns:
        True if token appears to have Resource Graph access
    """
    if not verbose:
        return True  # Assume it's fine if not debugging
    
    payload = decode_jwt_payload(token)
    if not payload:
        return False
    
    # Check if the audience includes Azure Resource Manager
    aud = payload.get('aud', '')
    scp = payload.get('scp', '')
    
    print("🔍 RESOURCE GRAPH API ACCESS CHECK:")
    print(f"  Audience: {aud}")
    print(f"  Scopes: {scp}")
    
    # For Resource Graph, we typically need the Azure Resource Manager audience
    # and user_impersonation scope
    if 'https://management.azure.com/' in aud or 'https://management.core.windows.net/' in aud:
        print("✅ Token audience includes Azure Resource Manager")
        has_audience = True
    else:
        print("⚠️  Token audience may not include Azure Resource Manager")
        has_audience = False
    
    if 'user_impersonation' in scp:
        print("✅ Token has user_impersonation scope")
        has_scope = True
    else:
        print("⚠️  Token may not have user_impersonation scope")
        has_scope = False
    
    result = has_audience and has_scope
    if result:
        print("✅ Token should work with Resource Graph API")
    else:
        print("⚠️  Token may have issues with Resource Graph API")
    
    print()
    return result
