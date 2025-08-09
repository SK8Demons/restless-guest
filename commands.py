
"""
Command handling logic for Azure Guest Access Management Tool.
This module contains all the business logic for the different commands.
"""

import logging
import sys
import uuid
from typing import Any, Dict, List, Optional
from pprint import pprint

# Import our custom modules
import config as cfg
import auth
import jwt_utils
import arm_api
import graph_api
import json

def handle_subiam_command(args: Any) -> int:
    """
    Handle the sub iam command - enumerate subscription role assignments for a given subscription.
    Args:
        args: Command line arguments namespace
    Returns:
        Exit code (0 for success, 1 for error)
    """
    resource = cfg.AZURE_RESOURCE
    client = cfg.POWERSHELL_APP_ID
    tenant = getattr(args, 'tenant_id', None)
    subscription_id = getattr(args, 'subscription_id', None)

    if not subscription_id:
        logging.error("Subscription ID is required for assignments command")
        return 1

    # If user supplies a refresh token, use it to get the initial access token
    if getattr(args, 'refresh_token', None):
        arm_token, refresh_token = auth.get_token_from_refresh(args.refresh_token, resource, client, tenant)
    else:
        arm_token, refresh_token = auth.get_token(args, resource, client, tenant)
    if not arm_token:
        logging.error("Failed to obtain authentication token")
        return 1

    # Verbose: inspect JWT claims (only all claims section)
    if getattr(args, 'verbose', False):
        print("=== JWT ALL CLAIMS ===")
        jwt_utils.inspect_azure_token(arm_token, True, only_all_claims=True)

    assignments = arm_api.enum_role_assignments(arm_token, subscription_id)

    # Switch to Graph API for principal lookups
    resource = cfg.GRAPH_RESOURCE
    client = cfg.OFFICE_365_MANAGEMENT_APP_ID
    graph_token, refresh_token = auth.get_token_from_refresh(refresh_token, resource, client, tenant)
    if not graph_token:
        logging.error("Failed to get Graph API token")
        return 1

    pids = parse_principal_ids(assignments)
    lookup_map = {}
    lookups = {"value": []}
    if pids:
        try:
            lookups = graph_api.lookup_principal_ids(graph_token, tenant, pids)
            for item in lookups.get('value', []):
                pid = item.get('id')
                if pid:
                    lookup_map[pid] = item
        except Exception as e:
            logging.warning(f"Graph API lookup failed: {e}")
            lookups = {"value": []}

    # Dynamically fetch built-in and custom role definitions from ARM API

    all_roles = arm_api.get_all_role_definitions(arm_token, subscription_id)

    paired_results = []
    for assignment in assignments:
        props = assignment.get('properties', {})
        principal_id = props.get('principalId')
        graph_info = lookup_map.get(principal_id)
        role_def = arm_api.get_role_def_by_id(all_roles, props.get('roleDefinitionId'))
        arm_assignment = dict(assignment)
        if role_def:
            arm_assignment["roleDefinition"] = role_def
        paired_results.append({
            "arm_assignment": arm_assignment,
            "graph_lookup": graph_info
        })

    if getattr(args, "json", False):
        print(json.dumps({"results": paired_results}, indent=2))
    else:
        print(f"\n✅ ARM Role Assignments query returned {len(assignments)} result(s)\n")
        if paired_results:
            print(f"🔐 Found {len(paired_results)} role assignment(s):\n")
        for idx, pair in enumerate(paired_results, 1):
            assignment = pair["arm_assignment"]
            graph_info = pair["graph_lookup"]
            props = assignment.get('properties', {})
            principal_id = props.get('principalId')
            principal_type = props.get('principalType')
            role = props.get('roleDefinitionId')
            scope = props.get('scope')
            role_def = assignment.get("roleDefinition")
            friendly_role = role_def["properties"]["roleName"] if role_def else "Unknown"
            
            print(f"\n🔐 {idx}. Principal ID: {principal_id}")
            print(f"   • Principal Type: {principal_type}")
            print(f"   • RBAC Role ID: {role.split('/')[-1]}")
            print(f"   • Role Name: {friendly_role}")
            print(f"   • Scope: {scope}")
            if graph_info:
                display_name = graph_info.get('displayName', 'N/A')
                user_type = graph_info.get('@odata.type', 'N/A')
                mail = graph_info.get('mail', 'N/A')
                upn = graph_info.get('userPrincipalName', 'N/A')

                print(f"   👤 Graph Lookup:")
                print(f"      • Display Name: {display_name}")
                print(f"      • Type: {user_type}")
                print(f"      • Email: {mail}")
                print(f"      • UserPrincipalName: {upn}")
            else:
                print(f"   👤 Graph Lookup: Not found or error")
        else:
            print("   ----------------------------------------")
            print("No assignments found!")
        print("\n================================================================================\n📊 SUMMARY\n🔐 Total Role Assignments: {}\n👤 Total Principal Lookups: {}\n".format(len(assignments), len(lookup_map)))
    return 0


def choose_target_tenant(tenants: List[Dict[str, Any]], username: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Allow user to interactively choose a target tenant from available tenants.
    Optionally filters out tenants that match the user's home domain if username provided.
    
    Args:
        tenants: List of tenant objects
        username: Username to extract domain from (optional)
        
    Returns:
        Selected tenant dict or None if no valid targets
    """
    targets = []
    for t in tenants:
        
        targets.append(t)
        print(f"{len(targets)} = {t.get('displayName')} ({t.get('tenantId')})")

    if len(targets) == 0:
        logging.error("No target resource tenants available!")
        return None
    chosen = choose_selection('Choose a target tenant: ', len(targets))
    return targets[chosen]


def choose_selection(msg: str, max_value: int) -> int:
    """
    Interactive selection helper that prompts user to choose from numbered options.
    
    Args:
        msg: Message to display to user
        max_value: Maximum valid selection number
        
    Returns:
        Zero-based index of user's selection
    """
    chosen = False

    while not chosen:
        try:
            chosen = int(input(msg))
            if chosen > max_value or chosen < 1:
                print('INVALID CHOICE! Choose again...')
                chosen = False
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit(0)
        except ValueError:
            print('INVALID CHOICE! Choose again...')
            chosen = False

    return chosen - 1


def choose_invoice_section(inv_secs: List[str]) -> str:
    """
    Allow user to interactively choose an invoice section from available options.
    
    Args:
        inv_secs: List of invoice section IDs
        
    Returns:
        Selected invoice section ID
    """
    for i in range(len(inv_secs)):
        print(f'{i+1} = {inv_secs[i]}')

    chosen = choose_selection('Choose an invoice section to create a subscription in: ', len(inv_secs))
    return inv_secs[chosen]


def choose_subscription(subs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Allow user to interactively choose a subscription from available options.
    
    Args:
        subs: List of subscription objects
        
    Returns:
        Selected subscription dict
    """
    for i in range(len(subs)):
        sub = subs[i]
        sub_id = sub.get("subscriptionId")
        name = sub.get("displayName")
        print(f"{i+1} - {name} ({sub_id})")

    chosen = choose_selection("Choose a subscription: ", len(subs))
    return subs[chosen]


def parse_principal_ids(assignments: List[Dict[str, Any]], object_type: Optional[str] = None) -> List[str]:
    """
    Extract principal IDs from role assignments, optionally filtered by type.
    
    Args:
        assignments: List of role assignment objects
        object_type: Filter by principal type ("User", "ServicePrincipal", etc.)
        
    Returns:
        List of principal ID strings
    """
    pids = []
    for assignment in assignments:
        principal_type = assignment.get('properties', {}).get('principalType')
        if object_type and principal_type and principal_type.lower() != object_type.lower():
            continue
        pid = assignment.get('properties', {}).get('principalId')
        if pid:
            pids.append(pid)

    return pids


def handle_invite_command(args: Any) -> int:
    """
    Handle the invite command - invite a user to a tenant.
    
    Args:
        args: Command line arguments namespace
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    if not args.email:
        logging.error("Email address is required for invite command")
        return 1
        
    resource = cfg.GRAPH_RESOURCE
    client = cfg.AZURE_APP_ID
    tenant = getattr(args, 'tenant_id', None)

    token, _ = auth.get_token(args, resource, client, tenant)
    if not token:
        logging.error("Failed to obtain authentication token")
        return 1
        
    result = graph_api.invite_user(token, args.email)
    if result:
        redeem_url = result.get('inviteRedeemUrl')
        print("User successfully invited!")
        print(f"IMPORTANT! Redeem invitation: {redeem_url}")
        return 0
    else:
        logging.error("Failed to invite user")
        return 1


def handle_createsub_command(args: Any) -> int:
    """
    Handle the createsub command - create a new subscription.
    
    Args:
        args: Command line arguments namespace
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    resource = cfg.AZURE_RESOURCE
    client = cfg.POWERSHELL_APP_ID
    token, refresh_token = auth.get_token(args, resource, client, None)
    
    if not token:
        logging.error("Failed to obtain authentication token")
        return 1

    
    
    # Get token for target tenant
    token, refresh_token = auth.get_token_from_refresh(refresh_token, resource, client, None)
    if not token:
        logging.error("Failed to get token for target tenant")
        return 1
        
    # Get invoice sections for subscription creation
    inv_secs = arm_api.get_invoice_sections(token)
    if not inv_secs:
        logging.error("No invoice sections found for subscription creation")
        return 1
        
    inv_sec = choose_invoice_section(inv_secs)
    sub_name = args.sub_name
    
    # print(f"Creating subscription '{sub_name}' in tenant {tenant_id}")
    result = arm_api.create_subscription(token, inv_sec, sub_name, args.tenant_id)
    
    if result:
        print("Subscription creation initiated successfully!")
        print(f"Response: {result}")
        return 0
    else:
        logging.error("Failed to create subscription")
        return 1


def handle_evilvm_command(args: Any) -> int:
    """
    Handle the evilvm command - create an Evil VM in a subscription.
    
    Args:
        args: Command line arguments namespace
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    if not args.region:
        logging.error("Region is required for evilvm command")
        return 1
        
    resource = cfg.AZURE_RESOURCE
    client = cfg.POWERSHELL_APP_ID
    token, refresh_token = auth.get_token(args, resource, client, args.tenant_id)
    
    if not token:
        logging.error("Failed to obtain authentication token")
        return 1

    # Get target subscription
    subscription_id = args.subscription_id
    
    if not subscription_id:
        # Let user choose from available subscriptions
        tenants = arm_api.get_tenants(token)
        if not tenants:
            logging.error("No tenants found")
            return 1
            
        target = choose_target_tenant(tenants, args.username)
        if not target:
            return 1
        tenant_id = target.get('tenantId')

        print(f"Selected tenant: {target.get('displayName')} ({tenant_id})")
        
        # Get token for target tenant
        token, refresh_token = auth.get_token_from_refresh(refresh_token, resource, client, tenant_id)
        if not token:
            logging.error("Failed to get token for target tenant")
            return 1
            
        # Get subscriptions in target tenant
        subs = arm_api.get_subscriptions(token)
        if not subs:
            logging.error("No subscriptions found in target tenant")
            return 1
            
        sub = choose_subscription(subs)
        subscription_id = sub.get('subscriptionId')
    
    print(f"Deploying Evil VM in subscription: {subscription_id}")
    print(f"Region: {args.region}")
    print(f"VM Name: {args.vm_name}")
    print(f"Admin Username: {args.admin_username}")
    
    try:
        # Create the Evil VM
        result = arm_api.create_evilvm(
            token=token,
            subscription_id=subscription_id,
            region=args.region,
            vm_name=args.vm_name,
            admin_username=args.admin_username,
            admin_password=args.admin_password
        )
        
        if result.get('status') == 'success':
            print("\nEvil VM deployment completed successfully!")
            print(f"VM Name: {result['vm_name']}")
            print(f"Resource Group: {result['resource_group']}")
            print(f"Region: {result['region']}")
            print(f"Admin Username: {result['admin_username']}")
            print(f"Resources Created: {', '.join(result['resources_created'])}")
            print("\nRDP Access:")
            print(f"  - VM will be accessible via RDP on port 3389")
            print(f"  - Use Azure AD credentials or local admin account")
            print(f"  - Public IP will be assigned dynamically")
            return 0
        else:
            logging.error("Evil VM deployment failed")
            return 1
            
    except Exception as e:
        logging.error(f"Failed to create Evil VM: {e}")
        return 1



def handle_mi_command(args: Any) -> int:
    """
    Handle the mi command - create a user-assigned managed identity with federated credentials.
    
    Args:
        args: Command line arguments namespace
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    if not args.resource_group:
        logging.error("Resource group is required for mi command")
        return 1
        
    resource = cfg.AZURE_RESOURCE
    client = cfg.POWERSHELL_APP_ID
    token, refresh_token = auth.get_token(args, resource, client, args.tenant_id)
    
    if not token:
        logging.error("Failed to obtain authentication token")
        return 1

    # Get target subscription
    subscription_id = args.subscription_id
    
    if not subscription_id:
        tenants = arm_api.get_tenants(token)
        if not tenants:
            logging.error("No tenants found")
            return 1
            
        target = choose_target_tenant(tenants, args.username)
        if not target:
            return 1
        tenant_id = target.get('tenantId')

        print(f"Selected tenant: {target.get('displayName')} ({tenant_id})")
        
        # Get token for target tenant
        token, refresh_token = auth.get_token_from_refresh(refresh_token, resource, client, tenant_id)
        if not token:
            logging.error("Failed to get token for target tenant")
            return 1
            
        # Get subscriptions in target tenant
        subs = arm_api.get_subscriptions(token)
        if not subs:
            logging.error("No subscriptions found in target tenant")
            return 1
            
        sub = choose_subscription(subs)
        subscription_id = sub.get('subscriptionId')
    
    print(f"Creating managed identity in subscription: {subscription_id}")
    print(f"Resource Group: {args.resource_group}")
    print(f"Identity Name: {args.identity_name}")
    print(f"Region: {args.region}")
    
    # Create the user-assigned managed identity
    identity_result = arm_api.create_user_assigned_identity(
        token=token,
        subscription_id=subscription_id,
        resource_group_name=args.resource_group,
        identity_name=args.identity_name,
        region=args.region
    )
    
    if not identity_result:
        logging.error("Failed to create managed identity")
        return 1
    
    print("Successfully created managed identity!")
    print(f"Identity ID: {identity_result.get('id')}")
    print(f"Principal ID: {identity_result.get('properties', {}).get('principalId')}")
    print(f"Client ID: {identity_result.get('properties', {}).get('clientId')}")
    
    # Create federated identity credential if parameters provided
    if args.issuer and args.subject:
        print(f"\nCreating federated identity credential...")
        print(f"Issuer: {args.issuer}")
        print(f"Subject: {args.subject}")
        print(f"Audiences: {args.audiences}")
        
        credential_result = arm_api.create_federated_identity_credential(
            token=token,
            subscription_id=subscription_id,
            resource_group_name=args.resource_group,
            identity_name=args.identity_name,
            credential_name=args.credential_name,
            issuer=args.issuer,
            subject=args.subject,
            audiences=args.audiences
        )
        
        if credential_result:
            print("Successfully created federated identity credential!")
            print(f"Credential ID: {credential_result.get('id')}")
            print(f"Credential Name: {credential_result.get('name')}")
        else:
            logging.error("Failed to create federated identity credential")
            return 1
    else:
        print("\nSkipping federated credential creation (issuer and subject not provided)")
    
    print(f"\nManaged identity setup completed!")
    print(f"Resource Group: {args.resource_group}")
    print(f"Identity Name: {args.identity_name}")
    
    return 0


def handle_defend_command(args: Any) -> int:
    """
    Handle the defend command - check external collaboration settings for security posture.
    
    Args:
        args: Command line arguments namespace
        
    Returns:
        Exit code (0 for success, 1 for error)
    """

    

    # Get ARM token for subscription policy settings
    arm_resource = cfg.AZURE_RESOURCE
    vs_client = cfg.VS_CODE_APP_ID
    tenant = getattr(args, 'tenant_id', None)

    arm_token, refresh_token = auth.get_token(args, arm_resource, vs_client, tenant)

    if not arm_token:
        logging.error("Failed to obtain ARM authentication token")
        return 1
    
    # Get subscription policy settings
    sub_policy = arm_api.get_subscription_policy_settings(arm_token)
    if not sub_policy:
        logging.error("Failed to retrieve subscription policy settings")
        return 1

    blockSubscriptionsIntoTenant = sub_policy.get('properties', {}).get("blockSubscriptionsIntoTenant", "unknown")
    print("=== GUEST SECURITY ASSESSMENT ===")
    print(f"\nSubscription creation / transfer policy")
    print("-----------------------------------------------")
    print(f"blockSubscriptionsIntoTenant: {blockSubscriptionsIntoTenant}")
    if not blockSubscriptionsIntoTenant:
        print("No restrictions on subscription transfers into the tenant")
        print("RISK! Sub creation / transfer into tenant is wide open to guests.")
    else:
        print("Restrictions on subscription transfers into the tenant")
        print("RISK BLOCKED! Restless guest sub attacks are not possible.")

    graph_resource = cfg.GRAPH_RESOURCE
    graph_token, _ = auth.get_token_from_refresh(refresh_token, graph_resource, vs_client, tenant)
    if not graph_token:
        logging.error("Failed to obtain authentication token")
        return 1
    
    
    # Get external collaboration settings
    settings = graph_api.get_external_collaboration_settings(graph_token)
    if not settings:
        logging.error("Failed to retrieve external collaboration settings")
        return 1


    allowInvitesFrom = settings.get('allowInvitesFrom', 'unknown')
    
    print(f"\nGuest Invite Policy")
    print("-----------------------------------------------")
    print(f"allowInvitesFrom: {allowInvitesFrom}:")
    if allowInvitesFrom == 'everyone':
        print("Anyone in the organization can invite guest users including guests and non-admins (most inclusive)")
        print("RISK! Even guests can invite guests!")
    elif allowInvitesFrom == 'adminsAndGuestInviter':
        print("Member users and users assigned to specific admin roles can invite guest users including guests with member permissions")
    elif allowInvitesFrom == 'adminsGuestInviterAndGuestInvite':
        print("Only users assigned to specific admin roles can invite guest users")
    elif allowInvitesFrom == 'none':
        print("No one in the organization can invite guest users including admins (most restrictive)")
    else:
        print(f"Custom setting: {allowInvitesFrom}")

    guestUserRoleId = settings.get('guestUserRoleId', 'unknown')
    print(f"\nGuest User Access Level")
    print("-----------------------------------------------")
    print(f"guestUserRoleId: {guestUserRoleId}):")
    if guestUserRoleId == 'a0b1b346-4d3e-4e8b-98f8-753987be4970': 
        print("Guest users have the same access as members (most inclusive)")
        print("RISK! List everything a normal user can!")
    elif guestUserRoleId == '10dae51f-b6af-4016-8d66-8c2a99b929b3':
        print("Guest users have limited access to properties and memberships of directory objects (default)")
        print("RIST! Enumerate management group principal ids and lookup technique possible!")
    elif guestUserRoleId == '2af84b1e-32c8-42b7-82bc-daa82404023b':
        print("Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)")
        print("RISK! Enumerate management group principal only!")
    else:
        print(f"Unknown/Custom setting: {guestUserRoleId}")

    print("")
    return 0


def handle_tenants_command(args: Any) -> int:
    """
    Handle the tenants command - list accessible Azure tenants.
    
    Args:
        args: Command line arguments namespace
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    resource = cfg.AZURE_RESOURCE
    client = cfg.POWERSHELL_APP_ID
    token, refresh_token = auth.get_token(args, resource, client, None)
    
    if not token:
        logging.error("Failed to obtain authentication token")
        return 1

    tenants = arm_api.get_tenants(token)
    if not tenants:
        logging.error("No tenants found or failed to retrieve tenants")
        return 1
    
    print("=== ACCESSIBLE AZURE TENANTS ===")
    print(f"Found {len(tenants)} accessible tenant(s):\n")
    
    for i, tenant in enumerate(tenants, 1):
        tenant_id = tenant.get('tenantId', 'Unknown')
        display_name = tenant.get('displayName', 'No display name')
        domain_name = tenant.get('defaultDomain', 'No domain')
        tenant_type = tenant.get('tenantType', 'Unknown')
        
        print(f"{i}. {display_name}")
        print(f"   Tenant ID: {tenant_id}")
        print(f"   Domain: {domain_name}")
        print(f"   Type: {tenant_type}")
        print()
    return 0


def handle_subassign_command(args: Any) -> int:
    """
    Handle the sub assign command - assign a specific RBAC role to a principal.
    
    Args:
        args: Command line arguments namespace
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    resource = cfg.AZURE_RESOURCE
    client = cfg.POWERSHELL_APP_ID
    tenant = getattr(args, 'tenant_id', None)
    subscription_id = getattr(args, 'subscription_id', None)
    principal_id = getattr(args, 'principal_id', None)
    role_id = getattr(args, 'role_id', None)
    principal_type = getattr(args, 'principal_type', 'User')
    scope = getattr(args, 'scope', None)
    delete_mode = getattr(args, 'delete', False)

    if not subscription_id:
        logging.error("Subscription ID is required for assign command")
        return 1
    
    if not principal_id:
        logging.error("Principal ID is required for assign command")
        return 1
        
    if not role_id:
        logging.error("Role ID is required for assign command")
        return 1

    # Get token for ARM operations
    if getattr(args, 'refresh_token', None):
        arm_token, refresh_token = auth.get_token_from_refresh(args.refresh_token, resource, client, tenant)
    else:
        arm_token, refresh_token = auth.get_token(args, resource, client, tenant)
    if not arm_token:
        logging.error("Failed to obtain authentication token")
        return 1

    # Inspect JWT token if verbose mode is enabled
    jwt_utils.inspect_azure_token(arm_token, getattr(args, 'verbose', False))

    # Build the role definition ID - if it's just a UUID, build the full path
    if "/" not in role_id:
        role_definition_id = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_id}"
    else:
        role_definition_id = role_id

    # Default scope to subscription if not provided
    if not scope:
        scope = f"/subscriptions/{subscription_id}"

    print(f"Principal ID: {principal_id}")
    print(f"Principal Type: {principal_type}")
    if not delete_mode:
        print(f"Role Definition ID: {role_definition_id}")
    print(f"Scope: {scope}")
    if delete_mode:
        print(f"Delete mode: Will remove existing assignments at this scope")
    print()

    # Handle delete mode - remove existing role assignments and exit
    if delete_mode:
        print("🗑️  Delete mode: Removing existing role assignments...")
        existing_assignments = arm_api.get_principal_role_assignments_at_scope(
            token=arm_token,
            subscription_id=subscription_id,
            principal_id=principal_id,
            scope=scope
        )
        
        if existing_assignments:
            print(f"Found {len(existing_assignments)} existing assignment(s) to remove")
            removed_count = 0
            for assignment in existing_assignments:
                assignment_name = assignment.get('name')
                if assignment_name:
                    print(f"Removing assignment: {assignment_name}")
                    if arm_api.remove_role_assignment(arm_token, subscription_id, assignment_name, scope):
                        removed_count += 1
                        print(f"  ✅ Successfully removed")
                    else:
                        print(f"  ❌ Failed to remove")
                        logging.warning(f"Failed to remove assignment {assignment_name}")
            print(f"Removed {removed_count}/{len(existing_assignments)} existing assignments")
            
            if removed_count > 0:
                print("✅ Role assignment deletion completed!")
                return 0
            else:
                logging.error("❌ Failed to remove any role assignments")
                return 1
        else:
            print("No existing assignments found at this scope")
            print("✅ No assignments to delete")
            return 0

    # Perform the role assignment (only if not in delete mode)
    if not delete_mode:
        print("Assigning new role...")
        try:
            result = arm_api.assign_role(
                token=arm_token,
                subscription_id=subscription_id,
                principal_id=principal_id,
                role_definition_id=role_definition_id,
                principal_type=principal_type,  # Use the configurable principal type
                scope=scope  # Pass the custom scope
            )
            
            if result:
                print("✅ Role assignment successful!")
                print(f"Assignment ID: {result.get('name', 'Unknown')}")
                print(f"Assignment details: {result}")
                return 0
            else:
                logging.error("❌ Role assignment failed")
                return 1
                
        except Exception as e:
            logging.error(f"Failed to assign role: {e}")
            return 1


def handle_listsub_command(args: Any) -> int:
    """
    Handle the sub list command - list accessible Azure subscriptions.
    
    Args:
        args: Command line arguments namespace
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    resource = cfg.AZURE_RESOURCE
    client = cfg.POWERSHELL_APP_ID
    token, refresh_token = auth.get_token(args, resource, client, None)
    
    if not token:
        logging.error("Failed to obtain authentication token")
        return 1

    # Get tenants first to show context
    tenants = arm_api.get_tenants(token)
    if not tenants:
        logging.error("No tenants found")
        return 1
    
    print("=== ACCESSIBLE AZURE SUBSCRIPTIONS ===")
    
    for tenant in tenants:
        tenant_id = tenant.get('tenantId')
        tenant_name = tenant.get('displayName', 'Unknown Tenant')
        
        print(f"\nTenant: {tenant_name} ({tenant_id})")
        print("-" * 50)
        
        # Get token for this specific tenant
        tenant_token, _ = auth.get_token_from_refresh(refresh_token, resource, client, tenant_id)
        if not tenant_token:
            print("  ⚠️  Failed to get token for this tenant")
            continue
            
        # Get subscriptions for this tenant
        subscriptions = arm_api.get_subscriptions(tenant_token)
        if not subscriptions:
            print("  No subscriptions found in this tenant")
            continue
            
        for i, sub in enumerate(subscriptions, 1):
            sub_id = sub.get('subscriptionId', 'Unknown')
            sub_name = sub.get('displayName', 'No display name')
            state = sub.get('state', 'Unknown')
            
            # Add emoji for state
            state_emoji = "✅" if state == "Enabled" else "❌" if state == "Disabled" else "⚠️"
            
            print(f"  {i}. {sub_name}")
            print(f"     Subscription ID: {sub_id}")
            print(f"     State: {state_emoji} {state}")
            print()
    
    return 0


def handle_transfersub_command(args: Any) -> int:
    """
    Handle the sub transfer command - transfer a subscription to another tenant.
    
    Args:
        args: Command line arguments namespace
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    if not args.subscription_id:
        logging.error("Subscription ID is required for transfer command")
        return 1
        
    if not args.target_tenant_id:
        logging.error("Target tenant ID is required for transfer command")
        return 1

    resource = cfg.AZURE_RESOURCE
    client = cfg.POWERSHELL_APP_ID
    token, _ = auth.get_token(args, resource, client, None)
    
    if not token:
        logging.error("Failed to obtain authentication token")
        return 1

    print("=== SUBSCRIPTION TRANSFER ===")
    print(f"Subscription ID: {args.subscription_id}")
    print(f"Target Tenant ID: {args.target_tenant_id}")
    print()
    
    # Confirm the operation
    confirm = input("Are you sure you want to transfer this subscription? This action cannot be undone. (yes/no): ")
    if confirm.lower() not in ['yes', 'y']:
        print("Transfer cancelled by user.")
        return 0
    
    print("Initiating subscription transfer...")
    
    result = arm_api.transfer_subscription(token, args.subscription_id, args.target_tenant_id)
    
    if result:
        print("✅ Subscription transfer initiated successfully!")
        
        if result.get("status") == "accepted":
            print("📋 Transfer Status: Accepted and being processed")
            print("⏳ The transfer may take several minutes to complete")
        else:
            print("📋 Transfer Details:")
            for key, value in result.items():
                print(f"   {key}: {value}")
        
        print()
        print("🔍 Next Steps:")
        print("1. Monitor the subscription in both tenants")
        print("2. Verify the transfer completed successfully")
        print("3. Update any automation or scripts that reference this subscription")
        print("4. Review access permissions in the new tenant")
        
        return 0
    else:
        print("❌ Failed to transfer subscription")
        print("🔍 Possible reasons:")
        print("- Insufficient permissions (need to be a billing administrator)")
        print("- Invalid subscription or tenant ID")
        print("- Subscription may already be in the target tenant")
        print("- Network or API issues")
        return 1


def handle_subresources_command(args: Any) -> int:
    """
    Handle the sub resources command - list all resources in a subscription.
    
    Args:
        args: Command line arguments namespace
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    if not args.subscription_id:
        logging.error("Subscription ID is required for resources command")
        return 1

    resource = cfg.AZURE_RESOURCE
    client = cfg.POWERSHELL_APP_ID
    token, refresh_token = auth.get_token(args, resource, client, args.tenant_id)
    
    if not token:
        logging.error("Failed to obtain authentication token")
        return 1

    # Inspect JWT token if verbose mode is enabled
    jwt_utils.inspect_azure_token(token, getattr(args, 'verbose', False))
    
    # Check token scopes for Resource Graph API
    jwt_utils.inspect_token_scopes_for_resource_graph(token, getattr(args, 'verbose', False))

    print("=== SUBSCRIPTION RESOURCES ===")
    print(f"Subscription ID: {args.subscription_id}")
    print()
    
    # Use Resource Graph API to get comprehensive resource data
    graph_data = arm_api.query_resources_with_resource_graph(token, args.subscription_id, getattr(args, 'verbose', False))
    
    if graph_data.get("status") == "error":
        print("Failed to retrieve resources using Resource Graph API.")
        print(f"Error: {graph_data.get('error', 'Unknown error')}")
        print()
        print("🔍 Possible reasons:")
        print("- Subscription ID is invalid")
        print("- No access to the subscription or Resource Graph API")
        print("- Network or API issues")
        return 1
    
    resource_groups = graph_data.get("resource_groups", [])
    all_resources = graph_data.get("resources", [])
    
    if not resource_groups:
        print("No resource groups found in this subscription.")
        print()
        print("🔍 Possible reasons:")
        print("- Subscription ID is invalid")
        print("- No access to the subscription")
        print("- Subscription has no resource groups")
        return 1
    
    print(f"📁 Found {len(resource_groups)} resource group(s):\n")
    
    # Group resources by resource group
    resources_by_rg = {}
    for resource in all_resources:
        rg_name = resource.get('resourceGroup', 'Unknown')
        if rg_name:
            rg_name_key = rg_name.lower()
        else:
            rg_name_key = 'unknown'
        if rg_name_key not in resources_by_rg:
            resources_by_rg[rg_name_key] = []
        resources_by_rg[rg_name_key].append(resource)

    total_resources = len(all_resources)

    for i, rg in enumerate(resource_groups, 1):
        rg_name = rg.get('name', 'Unknown')
        rg_name_key = rg_name.lower() if rg_name else 'unknown'
        location = rg.get('location', 'Unknown')
        rg_id = rg.get('id', 'Unknown')
        managed_by = rg.get('properties', {}).get('managedBy', None)
        status = rg.get('status', 'Unknown')

        # Add emoji for status
        state_emoji = "✅" if status == "Succeeded" else "⚠️" if status == "Failed" else "🔄" if status in ["Creating", "Deleting"] else "❌" if status == "Deleted" else "�"

        print(f"📁 {i}. Resource Group: {rg_name}")
        print(f"   📍 Location: {location}")
        print(f"   📊 Status: {state_emoji} {status}")
        if managed_by:
            print(f"   👤 Managed By: {managed_by}")

        # Get tags if they exist
        tags = rg.get('tags', {})
        if tags:
            print(f"   🏷️  Tags:")
            for key, value in tags.items():
                print(f"     {key}: {value}")

        # Get resources in this resource group from our grouped data (case-insensitive)
        rg_resources = resources_by_rg.get(rg_name_key, [])

        if rg_resources:
            print(f"   🔧 Resources ({len(rg_resources)}):")

            # Group resources by type for better organization
            resources_by_type = {}
            for resource in rg_resources:
                resource_type = resource.get('type', 'Unknown')
                if resource_type not in resources_by_type:
                    resources_by_type[resource_type] = []
                resources_by_type[resource_type].append(resource)

            for resource_type, type_resources in resources_by_type.items():
                print(f"     📦 {resource_type} ({len(type_resources)}):")

                for resource in type_resources:
                    resource_name = resource.get('name', 'Unknown')
                    resource_location = resource.get('location', 'Unknown')
                    resource_sku = resource.get('sku', {})
                    resource_kind = resource.get('kind', None)

                    print(f"       • {resource_name}")
                    if resource_location != location:  # Only show if different from RG location
                        print(f"         📍 Location: {resource_location}")

                    if resource_sku:
                        sku_name = resource_sku.get('name', 'Unknown')
                        sku_tier = resource_sku.get('tier', '')
                        if sku_tier:
                            print(f"         💰 SKU: {sku_name} ({sku_tier})")
                        else:
                            print(f"         💰 SKU: {sku_name}")

                    if resource_kind:
                        print(f"         🎯 Kind: {resource_kind}")

                    # Show resource tags if different from RG tags
                    resource_tags = resource.get('tags', {})
                    if resource_tags and resource_tags != tags:
                        print(f"         🏷️  Tags: {', '.join([f'{k}:{v}' for k, v in resource_tags.items()])}")

                print()  # Space between resource types
        else:
            print(f"   📭 No resources found in this resource group")

        print(f"   🆔 Resource Group ID: {rg_id}")
        print("-" * 80)
        print()
    
    print("=" * 80)
    print(f"📊 SUMMARY")
    print(f"📁 Total Resource Groups: {len(resource_groups)}")
    print(f"🔧 Total Resources: {total_resources}")
    
    return 0
