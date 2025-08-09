# restless guest 

<img alt="restless-guest-logo" src="https://github.com/HothIndustries/restless-guest/blob/main/logo.png?raw=true"/>

A cli toolkit for "restless guest" exploits. See [Pt 1](https://www.beyondtrust.com/blog/entry/restless-guests), [Pt 2](https://www.beyondtrust.com/blog/entry/evil-vm) blogs. 

This tool enables Entra (Azure AD) tenant attacks through "restless guest". The key concept we exploit is that by being a billing administrator from an attacker-controlled tenant, by default, we can create subscriptions in target tenants. This enables:

- Enumerate Entra principal id role assignments to the subscription resource
    - typically apps, groups or individual admins inherited from root management group
    - If guest has sufficient privs, they can also lookup mail, name, upn etc...
- Insert security principal with fedarated credentials (via managed-identity)
- Gain local admin backdoor to device identity principal
- Tell defenders what they need to fix

## definitions

- HOME TENANT - attacker controlled tenant
- RESOURCE TENANT = target tenant for attacker
- RESTLESS GUEST = guest in RESOURCE tenant who is a BILLING ADMIN user in HOME tenant
- BILLING ADMIN = user has a billing role in HOME tenant that allows them to create subscriptions
- EVIL VM = a vm that lacks TPM protection that is also a joined device

## dependencies

For attacker to fully use this tool they must have access to a user who as a BILLING ADMIN in a HOME tenant.

This is most easily achieved by signing up for an [azure free account](https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account?icid=azurefreeaccount). After signing up this user will be a BILLING ADMIN of the new account and it's associated entra tenant. IMPORTANT! microsoft live accounts, such as those from these signups, don't work well with non-interactive auth.

NOTE! To utilize the `persist` command fully attacker will first want to first setup an OIDC provider, [roadoidc](https://github.com/dirkjanm/ROADtools/tree/master/roadoidc) by @dirkjanm is the perfect tool and docs. [roadtx](https://github.com/dirkjanm/ROADtools/tree/master/roadtx) is also used heavily in this project 👏

## post exploitation steps

Comrpomise of any low privileged user / guest and a tenant with permissive settings will allow much mischief. This toolkit supports refresh-token authentication, non-interactive username+password auth, and interactive auth when mfa. Refresh token is most convenient for refresh token theft, or researchers using `roadtx`.

Let's show what an attack might look like end to end. 

### `invite`

First we exploit we can invite user's into tenant...

```
rlg invite --help
usage: rlg invite [-h] [auth options...] -e EMAIL

options:
  -h, --help            show this help message and exit
  -e, --email EMAIL     Invitee's email

```

### `sub create`

Now, as the attacker BILLING ADMIN in their HOME tenant, we create a subscription in the RESOURCE tenant. After this we will be a subscription owner in the RESOURCE TENANT...

```
rlg sub create --help
usage: rlg sub create [-h] [auth options...] [--sub-name SUB_NAME] [--sub-id SUB_ID]

options:
  -h, --help            show this help message and exit
  --sub-name SUB_NAME   New subscription name
  --tenant-id TENANT_ID Tenant ID that subscription will be created inside of


```

### `sub iam`

To gain the principal id, principal type and sometimes expanded details of principals in the directory, we can use enumerate them from the subscription RBAC role assignments...

```
rlg sub iam --help
usage: rlg sub iam [-h] [auth options...] --subscription-id SUBSCRIPTION_ID --tenant-id TENANT_ID [--json]

options:
  -h, --help            show this help message and exit
  --subscription-id SUBSCRIPTION_ID  Subscription ID to list IAM assignments from
  --tenant-id TENANT_ID         Tenant ID to list IAM assignments from
  --json                Output ARM and Graph API results as JSON

```

### `sub evilvm`


Gaining local admin to a device identity backdoor, opens up possible downstream PRT theft techniques...

1. Device code phish of specific refresh token, upgrade with device identity to gain PRT
2. Or, phish user to login to EVIL VM (using their Entra ID creds), we can steal the PRT issued to it upon login

```
rlg sub evilvm --help
usage: rlg sub evilvm [-h] [auth options...] [--region REGION] --vm-name VM_NAME [--admin-username ADMIN_USERNAME] [--admin-password ADMIN_PASSWORD] 
                          --subscription-id SUBSCRIPTION_ID --tenant-id TENANT_ID

options:
  -h, --help            show this help message and exit
  --region REGION       Azure region (default: eastus)
  --vm-name VM_NAME     VM name (default: GuestVM)
  --admin-username ADMIN_USERNAME    VM admin username (default: guestadmin)
  --admin-password ADMIN_PASSWORD    VM admin password (default: ComplexP@ssw0rd123!)
  --subscription-id SUBSCRIPTION_ID  Target subscription ID
  --tenant-id TENANT_ID         Tenant ID for VM creation

```

### `sub assign`

Expanding upon iam enumeration, we can assign specific RBAC roles scoped to the subscription, for any principal id. This can help us blend in the subscription, a single guest owner of a subscription looks very suspicious, making an existing admin an owner is much more legitimate. After we use a command like `persist` we can then `--delete` the guest's Owner role, to further obustucate the attack.

```
rlg sub assign --help
usage: rlg sub assign [-h] [auth options...] --subscription-id SUBSCRIPTION_ID --tenant-id TENANT_ID 
                          --principal-id PRINCIPAL_ID --role-id ROLE_ID [--principal-type {User,ServicePrincipal,Group}] [--scope SCOPE] [--delete]

options:
  -h, --help            show this help message and exit
  --subscription-id SUBSCRIPTION_ID  Subscription ID to assign role in
  --tenant-id TENANT_ID  Tenant ID for role assignment
  --principal-id PRINCIPAL_ID  Principal ID to assign role to
  --role-id ROLE_ID     RBAC role definition ID (UUID)
  --principal-type {User,ServicePrincipal,Group}  Type of principal (default: User)
  --scope SCOPE         Scope for role assignment (defaults to subscription scope)
  --delete              Delete existing role assignments for this principal at the specified scope (no new assignment will be made)

All commands accept authentication options described in the "auth options" section below.
```

### `sub persist`


If we wish to persist access away from guest account, we can add a security principal with fedarated credentials as in the RESOURCE tenant...

```
rlg sub persist --help
usage: rlg sub persist [-h] [auth options...] --resource-group RESOURCE_GROUP --identity-name IDENTITY_NAME [--region REGION] 
                           --subscription-id SUBSCRIPTION_ID --tenant-id TENANT_ID [--issuer ISSUER] [--subject SUBJECT] 
                           [--credential-name CREDENTIAL_NAME] [--audiences AUDIENCES [AUDIENCES ...]]

options:
  -h, --help            show this help message and exit
  --resource-group RESOURCE_GROUP  Resource group name
  --identity-name IDENTITY_NAME    Name of the managed identity to create
  --region REGION       Azure region to create resources in (default: eastus)
  --subscription-id SUBSCRIPTION_ID  Target subscription ID
  --tenant-id TENANT_ID         Target tenant ID
  --issuer ISSUER      JWT issuer for federated credentials
  --subject SUBJECT    JWT subject for federated credentials
  --credential-name CREDENTIAL_NAME  Name for the federated credential
  --audiences AUDIENCES [AUDIENCES ...]  Valid JWT audiences


  --identity-name IDENTITY_NAME   Managed identity name (default: GuestIdentity)
  --region REGION       Azure region (default: eastus)
  --subscription-id SUBSCRIPTION_ID  Target subscription ID
  --tenant-id TENANT_ID         Tenant ID for managed identity
  --issuer ISSUER      OIDC issuer URL for federated credential
  --subject SUBJECT    Subject identifier for federated credential
  --credential-name CREDENTIAL_NAME  Federated credential name (default: DefaultCredential)
  --audiences AUDIENCES Token audiences (default: api://AzureADTokenExchange)
```



## security assessment

To help defenders understand their exposure to restless guest attacks, we can check their tenant's external collaboration security settings. This requires admin access, though attacker can disover this posture settings by simply attacking the tenant and seeing what works.

### `defend`

```
rlg defend --help
usage: rlg defend [-h] [auth options...]

options:
  -h, --help  show this help message and exit
```

## additional commands

### `tenants`

List tenants authenticated user is a part of...

```
rlg tenants --help
usage: rlg tenants [-h] [auth options...]

options:
  -h, --help  show this help message and exit

```

List subscriptions we have access to in tenant
```

### `sub list`

List subscriptions in tenant user is authenticating to.

```
rlg sub list --help
usage: rlg sub list [-h] [auth options...] --tenant-id TENANT_ID

options:
  -h, --help            show this help message and exit
  --tenant-id TENANT_ID  Tenant ID to list resources from


```

### `sub resources`

```
rlg sub resources --help
usage: rlg sub resources [-h] [auth options...] --subscription-id SUBSCRIPTION_ID --tenant-id TENANT_ID

options:
  -h, --help            show this help message and exit
  --subscription-id SUBSCRIPTION_ID  Subscription ID to list resources from
  --tenant-id TENANT_ID         Tenant ID to list resources from

```


## auth options

We can supply our own `--refresh-token` like from phished user, or `roadtx` if you are exerpimenting. The tool aims to use foci client applications to increase chancees of phishable tokens by allowing any foci client refresh token to be interactive sign-in events being generated.

For convenience the following options can instead for basic auth, or interactive login. Both methods will store tokens in `.roadtools_auth`. 

2. `--username / -u` the username of the user principal user we are athenticating as
3. `--password / -p` password of user, ommitting will prompt input
2. `--interactive` will start a browser for full login, use if MFA required


## sources

- use local admin of device to steal device cert - https://aadinternals.com/post/deviceidentity/
- upgrade phished refresh token to PRT - https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens
- federated access via attacker provided OIDC - https://dirkjanm.io/persisting-with-federated-credentials-entra-apps-managed-identities/
- Setting up Entra ID login for VMs + Manual AAD Join (v interesting!) - https://akingscote.co.uk/posts/microsoft-azure-cross-tenant-vm-domain-join/

## blogs

- Pt 1. https://www.beyondtrust.com/blog/entry/restless-guests
- Pt 2. https://www.beyondtrust.com/blog/entry/evil-vm


## installation

```bash
git clone <repository-url>
cd restless-guest
pip install -r requirements.txt
```

