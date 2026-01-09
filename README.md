# IdentityChecker

IdentityChecker is a small PowerShell helper that gathers Microsoft Entra (Azure AD) and Azure DevOps identity data for a given user UPN, then runs a set of checks to surface common identity issues (UPN casing, OID mismatch, tenant mismatch, guest-role problems, license info, and profile status).

### Quick overview
- Collects Microsoft Graph user info using filter queries for robust external/guest user lookup (UPN, e-mail, object id, guest/member state, roles).
- Handles multiple matches gracefully with user selection when UPN or email matches multiple users.
- Collects Azure DevOps identity and entitlement info (VSID, tenant, account, OID, user type, license/entitlement).
- Checks Guest Inviter role status for guest users to determine if they can invite other external users.
- Calls the Azure DevOps Profiles API and surfaces profile state and profile error messages (useful for Access Denied / permission errors).

### Prerequisites
- PowerShell (Windows PowerShell or PowerShell Core).
- `Az` PowerShell module (the script will attempt to install it into the current user scope if missing).
- An account able to call Microsoft Graph and Azure DevOps APIs (you may need to run `Connect-AzAccount`).

### Usage
1. Open a PowerShell prompt in the repository folder containing `IdentityChecker.ps1`.
2. Run the script interactively:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File 'IdentityChecker.ps1'
```

3. Enter the Azure DevOps organization name and the UPN to inspect when prompted.
   - The script supports both internal and external/guest user UPNs, including formats like `user_company.com#EXT#@tenant.onmicrosoft.com`
   - If multiple users are found matching the UPN or email, you will be prompted to select the correct user by index.

### Handling External / Guest Users
The script uses filter queries to look up users in Microsoft Graph, which provides robust support for external and guest users with special characters in their UPNs (such as `#EXT#`). 

When checking a guest user, the script will:
- Verify the user's type (Member vs. Guest)
- Check if the user has the **Guest Inviter** role in Entra (required for guest users to invite other external users to Azure DevOps)
  - If missing, prompts to attempt adding the role via Graph API
  - If added successfully, instructions on how to verify the change
- Validate that the UPN and email are properly configured (mismatches can cause login/permission issues)
- Detect and display effective UPN formats for external users

### Fixing UPN Casing Mismatches
When a casing mismatch is detected between Entra and Azure DevOps UPNs, the script now:
- Explains the issue and its impact on Entra group/user queries
- Offers to automatically update the Entra UPN to match DevOps casing
- Provides detailed instructions for the user to propagate the change:
  - Log out of all Azure services and clear browser cache
  - Log into Azure DevOps with the corrected UPN
  - Changes should sync within a few minutes

Alternatively, if you prefer a different casing in DevOps, the script explains:
- The manual process to force DevOps to recognize a different casing (changing to a temporary UPN, having the user log in, changing back to the desired casing, then having the user log in again)
- How to open a support case with Microsoft for manual UPN casing updates in DevOps

### Force logout / switching accounts
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
- License / entitlement info from the User Entitlements API (licensing source, license type, last accessed date)
- Known scenarios validation:
  - **UPN Casing**: Detects and optionally fixes mismatches with automatic Entra updates
  - **OID**: Validates that the object ID matches between Entra and DevOps
  - **Tenant ID**: Ensures the user is in the correct tenant
  - **User Type**: Verifies consistency between internal/guest user types
  - **Guest Inviter Role**: For guest users, checks if they have the role needed to invite other guests (with option to add)
  - **Guest Email/UPN**: For guest users, validates proper UPN and email configuration

### Example output
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
Entra User State            : Internal
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
Licensing Source            : Assignment
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

### Troubleshooting
- If the script cannot obtain tokens, run `Connect-AzAccount` and ensure the account has appropriate permissions (Graph + DevOps).

### Extending / Contributing
- The script is intentionally small and easy to extend.

### Files
- `IdentityChecker.ps1`: Main script that performs all collection and checks.
- `LICENSE`: Repository license file.

### License & support
- See the repository `LICENSE` file for licensing details.
- For issues or feature requests, open an issue in the repository.

---
Written to help diagnose identity issues between Microsoft Entra and Azure DevOps.
