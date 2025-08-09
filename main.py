#!/usr/bin/env python3

import argparse
import logging
import sys

# Import our custom modules
import commands

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def art() -> None:
    print(r"""
          
   .-')     ('-.    .-')    .-') _               ('-.    .-')     .-')   
( ( OO )   _(  OO)  ( OO ). (  OO) )            _(  OO)  ( OO ).  ( OO ). 
,------. (,------.(_)---\_)/     '._ ,--.     (,------.(_)---\_)(_)---\_)
|   /`. ' |  .---'/    _ | |'--...__)|  |.-')  |  .---'/    _ | /    _ | 
|  /  | | |  |    \  :` `. '--.  .--'|  | OO ) |  |    \  :` `. \  :` `. 
|  |_.' | |  '--.  '..`''.)   |  |   |  |`-' | |  '--.  '..`''.) '..`''.)
|  .  '.' |  .--' .-._)   \   |  |   |  '---.' |  .--' .-._)   \.-._)   \
|  |\  \  |  `---.\       /   |  |   |      |  |  `---.\       /\       /
`--' '--' `------' `-----'    `--'   `------'  `------' `-----'  `-----' 

                           ('-.    .-')    .-') _    
                         _(  OO)  ( OO ). (  OO) )   
  ,----.    ,--. ,--.   (,------.(_)---\_)/     '._  
 '  .-./-') |  | |  |    |  .---'/    _ | |'--...__) 
 |  |_( OO )|  | | .-')  |  |    \  :` `. '--.  .--' 
 |  | .--, \|  |_|( OO ) |  '--.  '..`''.)   |  |    
(|  | '. (_/|  | | `-' / |  .--' .-._)   \   |  |    
 |  '--'  |('  '-'(_.-'  |  `---.\       /   |  |    
  `------'   `-----'     `------' `-----'    `--'    
  
  """)


def global_args(parser: argparse.ArgumentParser) -> None:
    """Add global arguments to the parser."""
    parser.add_argument("--refresh-token", help="Refresh token")
    parser.add_argument("-u", "--username", help="Username")
    parser.add_argument("-p", "--password", help="User's password")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output including JWT token inspection")

def main() -> int:
    """Main entry point for the application."""
    
    parser = argparse.ArgumentParser(description="Restless guest toolkit")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # sub command with subcommands
    sub_parser = subparsers.add_parser('sub', help='Subscription management')
    sub_subparsers = sub_parser.add_subparsers(dest='sub_command', required=True, help='Subscription operations')
    
    # sub create command
    sub_create_parser = sub_subparsers.add_parser('create', help='Create a subscription')
    global_args(sub_create_parser)
    sub_create_parser.add_argument("--sub-name", required=True, help="New subscription name")
    sub_create_parser.add_argument("--tenant-id", required=True, help="Tenant ID to create a subscription in")
    
    # sub list command
    sub_list_parser = sub_subparsers.add_parser('list', help='List accessible subscriptions')
    global_args(sub_list_parser)
    sub_list_parser.add_argument("--tenant-id", required=True, help="Tenant ID to list resources from")
    
    # sub transfer command
    sub_transfer_parser = sub_subparsers.add_parser('transfer', help='Transfer subscription to another tenant')
    global_args(sub_transfer_parser)
    sub_transfer_parser.add_argument("--subscription-id", required=True, help="Subscription ID to transfer")
    sub_transfer_parser.add_argument("--target-tenant-id", required=True, help="Target tenant ID to transfer subscription to")
    
    # sub resources command
    sub_resources_parser = sub_subparsers.add_parser('resources', help='List all resources in a subscription')
    global_args(sub_resources_parser)
    sub_resources_parser.add_argument("--subscription-id", required=True, help="Subscription ID to list resources from")
    sub_resources_parser.add_argument("--tenant-id", required=True, help="Tenant ID to list resources from")

    # sub iam command (was assignments)
    sub_iam_parser = sub_subparsers.add_parser('iam', help='List all IAM role assignments in a subscription')
    global_args(sub_iam_parser)
    sub_iam_parser.add_argument("--subscription-id", required=True, help="Subscription ID to list IAM assignments from")
    sub_iam_parser.add_argument("--tenant-id", required=True, help="Tenant ID to list IAM assignments from")
    sub_iam_parser.add_argument("--json", action="store_true", default=False, help="Output ARM and Graph API results as JSON")

    # sub evilvm command
    sub_evilvm_parser = sub_subparsers.add_parser('evilvm', help='Create an Evil VM')
    global_args(sub_evilvm_parser)
    sub_evilvm_parser.add_argument("--region", default="eastus", help="Azure region (default: eastus)")
    sub_evilvm_parser.add_argument("--vm-name", required=True, help="VM name (default: GuestVM)")
    sub_evilvm_parser.add_argument("--admin-username", default="guestadmin", help="VM admin username (default: guestadmin)")
    sub_evilvm_parser.add_argument("--admin-password", default="ComplexP@ssw0rd123!", help="VM admin password (default: ComplexP@ssw0rd123!)")
    sub_evilvm_parser.add_argument("--subscription-id", required=True, help="Target subscription ID")
    sub_evilvm_parser.add_argument("--tenant-id", required=True, help="Tenant ID for VM creation")

    # sub mi command
    sub_mi_parser = sub_subparsers.add_parser('persist', help='Create user-assigned managed identity with federated credentials')
    global_args(sub_mi_parser)
    sub_mi_parser.add_argument("--resource-group", required=True, help="Resource group name")
    sub_mi_parser.add_argument("--identity-name",  required=True, default="GuestIdentity", help="Managed identity name (default: GuestIdentity)")
    sub_mi_parser.add_argument("--region", default="eastus", help="Azure region (default: eastus)")
    sub_mi_parser.add_argument("--subscription-id", required=True, help="Target subscription ID")
    sub_mi_parser.add_argument("--tenant-id", required=True, help="Tenant ID for managed identity")
    sub_mi_parser.add_argument("--issuer", help="OIDC issuer URL for federated credential")
    sub_mi_parser.add_argument("--subject", help="Subject identifier for federated credential")
    sub_mi_parser.add_argument("--credential-name", default="DefaultCredential", help="Federated credential name (default: DefaultCredential)")
    sub_mi_parser.add_argument("--audiences", nargs='+', default=["api://AzureADTokenExchange"], help="Token audiences (default: api://AzureADTokenExchange)")

    sub_assign_parser = sub_subparsers.add_parser('assign', help='Assign RBAC role to a principal on subscription')
    global_args(sub_assign_parser)
    sub_assign_parser.add_argument("--subscription-id", required=True, help="Subscription ID to assign role in")
    sub_assign_parser.add_argument("--tenant-id", required=True, help="Tenant ID for role assignment")
    sub_assign_parser.add_argument("--principal-id", required=True, help="Principal ID to assign role to")
    sub_assign_parser.add_argument("--role-id", required=True, help="RBAC role definition ID (UUID)")
    sub_assign_parser.add_argument("--principal-type", default="User", choices=["User", "ServicePrincipal", "Group"], help="Type of principal (default: User)")
    sub_assign_parser.add_argument("--scope", help="Scope for role assignment (defaults to subscription scope)")
    sub_assign_parser.add_argument("--delete", action="store_true", default=False, help="Delete existing role assignments for this principal at the specified scope (no new assignment will be made)")
    

    # invite command
    invite_parser = subparsers.add_parser('invite', help='Invite a user')
    global_args(invite_parser)
    invite_parser.add_argument("-e", "--email", required=True, help="Invitee's email")
    invite_parser.add_argument("--tenant-id", help="Tenant ID for role assignment")


    # defend command
    defend_parser = subparsers.add_parser('defend', help='Check external collaboration security settings')
    global_args(defend_parser)

    # tenants command
    tenants_parser = subparsers.add_parser('tenants', help='List accessible Azure tenants')
    global_args(tenants_parser)

    # Check if help is being requested and show art
    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        art()

    args = parser.parse_args()
    
    # Handle commands using the commands module
    if args.command == "invite":
        return commands.handle_invite_command(args)
    elif args.command == "sub":
        if args.sub_command == "create":
            return commands.handle_createsub_command(args)
        elif args.sub_command == "list":
            return commands.handle_listsub_command(args)
        elif args.sub_command == "transfer":
            return commands.handle_transfersub_command(args)
        elif args.sub_command == "resources":
            return commands.handle_subresources_command(args)
        elif args.sub_command == "iam":
            return commands.handle_subiam_command(args)
        elif args.sub_command == "evilvm":
            return commands.handle_evilvm_command(args)
        elif args.sub_command == "persist":
            return commands.handle_mi_command(args)
        elif args.sub_command == "assign":
            return commands.handle_subassign_command(args)


        else:
            logging.error(f"Unknown sub command: {args.sub_command}")
            return 1
    
    elif args.command == "defend":
        return commands.handle_defend_command(args)
    elif args.command == "tenants":
        return commands.handle_tenants_command(args)

    else:
        logging.error(f"Unknown command: {args.command}")
        return 1
        
    return 0
    

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)