# IdentityChecker

IdentityChecker is a small PowerShell helper that gathers Microsoft Entra (Azure AD) and Azure DevOps identity data for a given user UPN, then runs a set of checks to surface common identity issues (UPN casing, OID mismatch, tenant mismatch, guest-role problems, license info, and profile status).

##Quick overview
- Collects Microsoft Graph user info (UPN, e-mail, object id, guest/member state, roles).
- Collects Azure DevOps identity and entitlement info (VSID, tenant, account, OID, user type, license/entitlement).
- Calls the Azure DevOps Profiles API and surfaces profile state and profile error messages (useful for Access Denied / permission errors).

###Prerequisites
- PowerShell (Windows PowerShell or PowerShell Core).
- `Az` PowerShell module (the script will attempt to install it into the current user scope if missing).
- An account able to call Microsoft Graph and Azure DevOps APIs (you may need to run `Connect-AzAccount`).

###Usage
1. Open a PowerShell prompt in the repository folder containing `IdentityChecker.ps1`.
2. Run the script interactively:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File 'IdentityChecker.ps1'
```

3. Enter the Azure DevOps organization name and the UPN to inspect when prompted.

###Force logout / switching accounts
--------------------------------

If your workstation has a cached Azure identity and you need to run the checks using a different account, use the `-ForceLogout` switch. This makes the script attempt to clear cached credentials before collecting tokens.

- What it does: runs `az logout` / `az account clear` (if Azure CLI is available) and `Disconnect-AzAccount` / `Clear-AzContext` (if Az PowerShell cmdlets are available). It then continues and will prompt you to sign-in again when tokens are requested.
- Example:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File 'IdentityChecker.ps1' -ForceLogout
```

What the script prints
- Logged-in user info (the account used to fetch tokens)
- Entra tenant and user details (display name, id, UPN, email, OID, member/guest state, Guest Inviter role)
- Azure DevOps identity details (VSID, tenant id, account name, email, OID, DevOps user type)
- License / entitlement info from the User Entitlements API
- Profile state and, on API errors, the Profiles API error payload including `customProperties` and `message` (useful for diagnosing access denied scenarios)

Example output
--------------
The following is example output you may see when running the script. Values are illustrative.

```text
--------------------------------------------------------------------------------------------
Logged in User Info:
--------------------------------------------------------------------------------------------
Logged into Entra as        : steve.rogers@contoso.com
Logged into Azure DevOps as : steve.rogers@contoso.com

--------------------------------------------------------------------------------------------
Entra and Entra User Info:
--------------------------------------------------------------------------------------------
Entra Tenant Name           : Contoso Ltd
Entra Tenant ID             : 0d49ce9f-27ea-4f77-9d99-fbd19afb6195
Entra User Principal Name   : steve.rogers@contoso.com
Entra User Email            : steve.rogers@contoso.com
Entra User OID              : 9561209c-26db-44c8-bd86-13b18aca4414
Entra User Type             : Member
Entra User is Guest Inviter : False

--------------------------------------------------------------------------------------------
Azure DevOps User Info:
--------------------------------------------------------------------------------------------
Devops User VSID            : bdecc96a-d3cc-471e-a4e4-11d0073b803b
Devops User Tenant ID       : 0d49ce9f-27ea-4f77-9d99-fbd19afb6195
DevOps User Account Name    : steve.rogers@contoso.com
DevOps User Email           : steve.rogers@contoso.com
DevOps User OID             : 9561209c-26db-44c8-bd86-13b18aca4414
DevOps User Type            : Member

--------------------------------------------------------------------------------------------
DevOps User License Info:
--------------------------------------------------------------------------------------------
License type                : Express
License Display Name        : Basic + Test Plans
Last Accessed Date          : 11/21/2025 10:32:15 AM

--------------------------------------------------------------------------------------------
Checking for Known Scenarios...
--------------------------------------------------------------------------------------------
UPN Casing matches.
OID matches.
Tenant ID matches.
User Type matches.
Not a Guest User, skipping Guest Role check.
Not a Guest User, skipping Entra Guest Info check.

```

###Troubleshooting
- If the script cannot obtain tokens, run `Connect-AzAccount` and ensure the account has appropriate permissions (Graph + DevOps).

###Extending / Contributing
- The script is intentionally small and easy to extend.

###Files
- `IdentityChecker.ps1`: Main script that performs all collection and checks.
- `LICENSE`: Repository license file.

###License & support
- See the repository `LICENSE` file for licensing details.
- For issues or feature requests, open an issue in the repository.

---
Generated to help diagnose identity issues between Microsoft Entra and Azure DevOps.
