# ===========================
# Script parameters
# ===========================
param(
    [switch]$ForceLogout
)
# ===========================
# Function: Test-Prerequisites
# ===========================
function Test-Prerequisites {
    param([switch]$ForceLogout)
    if ($ForceLogout) {
        Write-Host "ForceLogout requested: will attempt to log out and clear cached Azure credentials." -ForegroundColor Yellow
        # Prefer Azure CLI logout if available
        if (Get-Command az -ErrorAction SilentlyContinue) {
            try {
                az logout 2>$null
            }
            catch { }
            try {
                az account clear 2>$null
            }
            catch { }
        }

        # Also clear Az PowerShell contexts if the Az module is present
        if (Get-Command Disconnect-AzAccount -ErrorAction SilentlyContinue) {
            try { Disconnect-AzAccount -Scope CurrentUser -ErrorAction SilentlyContinue } catch { }
            try { Clear-AzContext -Force -ErrorAction SilentlyContinue } catch { }
        }
        try {
            Connect-AzAccount -WarningAction 'SilentlyContinue' -ErrorAction 'Stop' -InformationAction 'SilentlyContinue' -ProgressAction 'SilentlyContinue'
        }
        catch { }
        
    }

    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        Clear-Host
        Write-Host "It seems that the Az module is not installed or not working properly."
        Write-Host "Please wait while we attempt to install the Az module."
        Install-Module -Name Az -Repository PSGallery -Force -AllowClobber -Verbose -Scope CurrentUser -ErrorAction Stop
        Clear-Host
        Write-Host "Az module installed successfully."
        Connect-AzAccount -WarningAction 'SilentlyContinue' -ErrorAction 'Stop' -InformationAction 'SilentlyContinue' -ProgressAction 'SilentlyContinue'
    }
}

# ===========================
# Function: Get-AccessTokens
# as Azure CLI stores the credientals if you need to run this for a diffrent user we need to run AZ Login
# not quite sure how to prompt for this as most users will want the persistant login to work 
# with the smae org... but we need a way to notice if thecontext has changed
# ===========================
function Get-AccessTokens {
    $graphToken = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/"
    $plainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($graphToken.Token))
    $AuthHeader = "Bearer $plaintoken" 
    $graphToken | Add-Member -NotePropertyName 'AuthHeader' -NotePropertyValue $AuthHeader -Force
    $devopsToken = Get-AzAccessToken -ResourceUrl '499b84ac-1321-427f-aa17-267ca6975798'
    $plainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($devopsToken.Token))
    $AuthHeader = "Bearer $plainToken"
    $devopsToken | Add-Member -NotePropertyName 'AuthHeader' -NotePropertyValue $AuthHeader -Force
    return @{ Graph = $graphToken; DevOps = $devopsToken }
}

# ===========================
# Function: Get-TenantIdFromDevOps
# ===========================
function Get-TenantInfo {
    param([psobject]$GraphToken)
    $Graphapiurl = "https://graph.microsoft.com/v1.0/organization/$($GraphToken.TenantId)?`$select=Id,displayName"
    $headers = @{
        Authorization           = $GraphToken.AuthHeader
        "X-TFS-FedAuthRedirect" = "Suppress"
    }
    $response = Invoke-RestMethod -Uri $Graphapiurl -Headers $headers -Method Get
    return $response
}

# ===========================
# Function: Get-DevOpsUserInfo
# ===========================
function Get-DevOpsUserInfo {
    param([string]$OrgName, [psobject]$DevOpsToken, [string]$UserPrincipalName)
    $uri = "https://vssps.dev.azure.com/$OrgName/_apis/identities?searchFilter=General&filterValue=$UserPrincipalName&queryMembership=None&api-version=7.2-preview"
    $headers = @{
        Authorization           = $DevOpsToken.AuthHeader
        "X-TFS-FedAuthRedirect" = "Suppress"
    }
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    if ($response.count -eq 0) {
        Write-Warning "User not found in Azure DevOps."
    }
 return $response.value
}

# ===========================
# Function: Get-DevOpsUserLicense
# Retrieves Azure DevOps user entitlement/license for the given user id
# ===========================
function Get-DevOpsUserLicense {
    param([string]$OrgName, [psobject]$DevOpsToken, [string]$UserId)
    $uri = "https://vsaex.dev.azure.com/$OrgName/_apis/userentitlements/$($UserId)?api-version=7.2-preview.5"
    $headers = @{
        Authorization           = $DevOpsToken.AuthHeader
        "X-TFS-FedAuthRedirect" = "Suppress"
    }
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
        return $response
    }
    catch {
        Write-Warning "Could not retrieve license information from Azure DevOps."
        return $null
    }
}

# ===========================
# Function: Get-EntraUserInfo
# ===========================
function Get-EntraUserInfo {
    param([psobject]$GraphToken, [string]$UserPrincipalName)
    # Use filter query for better compatibility with external/guest users
    $uri = "https://graph.microsoft.com/v1.0/users?`$filter=((userPrincipalName eq '$([System.Uri]::EscapeDataString($UserPrincipalName))') or (Mail eq '$([System.Uri]::EscapeDataString($UserPrincipalName))'))&`$select=id,userPrincipalName,creationType,userType,externalUserState,displayName,mail"
    $headers = @{
        Authorization           = $GraphToken.AuthHeader
        "X-TFS-FedAuthRedirect" = "Suppress"
        ConsistencyLevel        = "eventual"
    }
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get

    if ($response.value.Count -eq 0) {
        Write-Warning "User '$UserPrincipalName' not found in Entra."
        return $null
    }
    $index = 0
    if ($response.value.Count -gt 1) {
        Write-Warning "Multiple users found in Entra with UPN or Mail matching '$UserPrincipalName'."
        foreach ($value in $response.value) {
            Write-Host "User $index UPN: $($value.userPrincipalName)"
            Write-Host "User $index Mail: $($value.mail)"
            Write-Host "User $index Id : $($value.id)"
            $index++
        }
        do {
            $index = Read-Host "Multiple users found. Please enter the index of the user to select (0 to $($response.value.Count - 1))"
        }   
        while (-not ($index -as [int]) -or $index -lt 0 -or $index -ge $response.value.Count)
    }
    $user = $response.value[$index]
    
    # Get the Guest Inviter role details from the directory
    $uri = "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=displayName eq 'Guest Inviter'"
    $headers = @{
        Authorization           = $GraphToken.AuthHeader
        "X-TFS-FedAuthRedirect" = "Suppress"
        ConsistencyLevel        = "eventual"
    }
    
    $roleResponse = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    
    if ($roleResponse.value.Count -eq 0) {
        Write-Host "Guest Inviter role not found in directory. You may need to activate this role first." -ForegroundColor Yellow
        return $false
    }
    $guestInviterRole = $roleResponse.value[0]
    $uri = "https://graph.microsoft.com/v1.0/directoryRoles/$($guestInviterRole.id)/members?`$filter=id eq '$($user.id)'"
    try
    { 
        $roles = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    }
    catch {
        $roles = $null
    }
    $user | Add-Member -NotePropertyName 'isGuestInviter' -NotePropertyValue (($null -eq $roles) -or ($roles.value.Count -eq 0) ? $false : $true) -Force
    return $user
}

# ===========================
# Function: Update-EntraUserPrincipalName
# ===========================
function Update-EntraUserPrincipalName {
    param([psobject]$GraphToken, [string]$UserId, [string]$oldUPN, [string]$NewUPN)
    
    try {
        $uri = "https://graph.microsoft.com/v1.0/users/$UserId"
        $headers = @{
            Authorization           = $GraphToken.AuthHeader
            "X-TFS-FedAuthRedirect" = "Suppress"
            "Content-Type"          = "application/json"
        }
        if ($oldUPN -like "*#EXT#*")
        {
            Write-Host "Converting UPN to external user format for Entra" -ForegroundColor DarkGray
            $upnParts = $oldUPN -split "#EXT#"
            $localPart = $NewUPN.Replace("@", "_")
            $domainPart = $upnParts[1]
            $NewUPN = "$($localPart)#EXT#$($domainPart)"
            Write-Host "Converted UPN : $NewUPN" -ForegroundColor DarkGray
        }
        $body = @{
            userPrincipalName = $NewUPN
        } | ConvertTo-Json
        
        Invoke-RestMethod -Uri $uri -Headers $headers -Method Patch -Body $body | Out-Null
        Write-Host "Successfully updated UPN in Entra to: $NewUPN" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Failed to update UPN in Entra: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ===========================
# Function: Compare-Casing
# ===========================
function Compare-Casing {
    param($DevOpsUser, $EntraUser, $GraphToken)
    $upn = $EntraUser.userPrincipalName
    

    if ($upn -like "*#EXT#*") 
    {
        Write-Host "External user detected, converting UPN format" -ForegroundColor DarkGray
        Write-Host "Entra UPN     : $upn" -ForegroundColor DarkGray
        $upnParts = $upn -split "#EXT#"
        $localPart = $upnParts[0].Replace("_", "@")
        $upn = $localPart
        Write-Host "Effective UPN : $upn" -ForegroundColor DarkGray
    }

    if ($DevOpsUser.properties.Account."`$value" -cne $upn ) 
    {
        Write-Host "--------------------------------------------------------------------------------------------"
        Write-Host "Casing mismatch detected: " -ForegroundColor Red
        Write-Host "DevOps = '$($DevOpsUser.properties.Account."`$value")'" -ForegroundColor Red
        Write-Host " vs" -ForegroundColor Red
        Write-Host "Entra  = '$($upn)'" -ForegroundColor Red
        Write-Host ""
        Write-Host "This mismatch can cause issues when attempting to read info from Entra such as groups or users."
        Write-Host "The recommended fix is to update the UPN in Entra to match DevOps casing."
        Write-Host ""
        Write-Host "If the casing in DevOps is not the desired format, you can open a support case to"
        Write-Host "have Microsoft update the UPN casing in DevOps to match Entra. Or you can follow these"
        Write-Host "steps to force the update to Devops (if the user is an Internal Member)"
        Write-Host "  1. Change the UPN in Entra to a temporary different value (e.g., append '_temp'"
        Write-Host "     to pre '@' portion of the UPN)"
        Write-Host "  2. Have the user log in to DevOps with the temporary UPN to update the DevOps data"
        Write-Host "     *Please use a private browsing session to avoid cached credentials.*"
        Write-Host "  3. Change the UPN in Entra back to the original content but with  desired casing"
        Write-Host "  4. Have the user log in to DevOps again to update the DevOps data with the correct" 
        Write-Host "     casing.  *Log out of all Azure services (including DevOps, Azure Portal, etc.)"
        Write-Host "     and clear browser cache/cookies for *.dev.azure.com and *.microsoft.com*"
        Write-Host ""
        $response = Read-Host "Would you like to update the Entra UPN to match DevOps? (Y/N)"
        if ($response -eq 'Y' -or $response -eq 'y') {
            $devopsUPN = $DevOpsUser.properties.Account."`$value"
            if (Update-EntraUserPrincipalName -GraphToken $GraphToken -UserId $EntraUser.id -OldUPN $EntraUser.userPrincipalName -NewUPN $devopsUPN) {
                Write-Host ""
                Write-Host "To propagate this change to Azure DevOps, the user must:" 
                Write-Host "  1. Log out of all Azure services (including DevOps, Azure Portal, etc.)"
                Write-Host "  2. Clear browser cache/cookies for *.dev.azure.com and *.microsoft.com"
                Write-Host "  3. Log into Azure DevOps with the corrected UPN: $devopsUPN"
                Write-Host "  4. Once successfully logged in, the casing should be synced to DevOps"
                Write-Host ""
                Write-Host "Note: This process may take a few minutes to fully propagate." 
            }
        }
        else {

        }
        Write-Host "--------------------------------------------------------------------------------------------"
    } 
    else 
    {
        Write-Host "UPN Casing matches." -ForegroundColor Green
    }
}

# ===========================
# Function: Compare-OID
# ===========================
function Compare-OID {
    param($DevOpsUser, $EntraUser)
    if ($DevOpsUser.properties."http://schemas.microsoft.com/identity/claims/objectidentifier"."`$value" -ne $EntraUser.Id) 
    {
        Write-Host "--------------------------------------------------------------------------------------------"
        Write-Host "OID mismatch detected:" -ForegroundColor Red
        Write-Host "DevOps = '$($DevOpsUser.properties."http://schemas.microsoft.com/identity/claims/objectidentifier"."`$value")'"
        Write-Host " vs" 
        Write-Host "Entra  = '$($EntraUser.id)'"  
        Write-Host "This can cause issues with login, authorization, and access to resources."
        Write-Host "Please have this user log into DevOps (if possible) to ensure that any changes in Entra"
        Write-Host "are fully synched to DevOps, then re-run this script to see if this resolves the issue."
        Write-Host "If it does not please open a support case with Microsoft and include this output."
        Write-Host "--------------------------------------------------------------------------------------------"
    } 
    else 
    {
        Write-Host "OID matches." -ForegroundColor Green
    }
}

# ===========================
# Function: Compare-TenantId    
# ===========================
function Compare-TenantId {
    param($DevOpsUser, $TenantId)
    if ($DevOpsUser.properties.Domain."`$value" -ne $TenantId.Id) 
    {
        Write-Host "--------------------------------------------------------------------------------------------"
        Write-Host "Tenant ID mismatch detected:" -ForegroundColor Red
        Write-Host "Tenant mismatch detected:"  -ForegroundColor Red 
        Write-Host "DevOps backed by = '$($DevOpsUser.properties.Domain."`$value")'"
        Write-Host " vs" 
        Write-Host "Entra user is in = '$($TenantId.Id)'"
        Write-Host "This WILL cause issues with login, authorization, and access to resources."
        Write-Host "Please verify that the user is logging in using the the correct tenant."
        Write-Host "It can be simpler to see this if you use a new private browsing session to login."
        Write-Host "If this does not resolve the issue, please open a support case with Microsoft and include" 
        Write-Host "this output."
        Write-Host "--------------------------------------------------------------------------------------------"
    } 
    else 
    {
        Write-Host "Tenant ID matches." -ForegroundColor Green
    }
}

# ===========================
# Function: Compare-UserType    
# ===========================
function Compare-UserType {
    param($DevOpsUser, $EntraUser)
    $entraType = "$($EntraUser.userType)"
    $devopsType = if ($DevOpsUser.properties.metaTypeId -eq 1) { "Guest" } elseif ($DevOpsUser.properties.metaTypeId -eq 0) { "Unknown" } else { "Member" }
    if ($entraType -ne $devopsType) 
    {
        Write-Host "--------------------------------------------------------------------------------------------"
        Write-Host "User Type mismatch detected:"  -ForegroundColor Red 
        Write-Host "DevOps = '$devopsType'"
        Write-Host " vs" 
        Write-Host "Entra  = '$entraType'"  
        Write-Host "Please have this user log into DevOps (if possible) to ensure that any changes in Entra"
        Write-Host "are fully synched to DevOps, then re-run this script to see if this resolves the issue."
        Write-Host "If it does not please open a support case with Microsoft and include this output."
        Write-Host "--------------------------------------------------------------------------------------------"
    } 
    else 
    {
        Write-Host "User Type matches." -ForegroundColor Green
    }
}

# ===========================
# Function: Add-GuestInviterRole
# ===========================
function Add-GuestInviterRole {
    param([psobject]$GraphToken, [string]$UserId)
    
    try {
        # Get the Guest Inviter role details from the directory
        $uri = "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=displayName eq 'Guest Inviter'"
        $headers = @{
            Authorization           = $GraphToken.AuthHeader
            "X-TFS-FedAuthRedirect" = "Suppress"
            ConsistencyLevel        = "eventual"
        }
        
        $roleResponse = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        if ($roleResponse.value.Count -eq 0) {
            Write-Host "Guest Inviter role not found in directory. You may need to activate this role first." -ForegroundColor Yellow
            return $false
        }
        
        $guestInviterRole = $roleResponse.value[0]
        
        # Add the user to the Guest Inviter role
        $uri = "https://graph.microsoft.com/v1.0/directoryRoles/$($guestInviterRole.id)/members/`$ref"
        $body = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$UserId"
        } | ConvertTo-Json
        
        Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $body -ContentType "application/json" | Out-Null
        Write-Host "Successfully added Guest Inviter role to user." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Failed to add Guest Inviter role: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ===========================
# Function: Compare-GuestRoles
# ===========================
function Compare-GuestRoles 
{
#     https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/add-external-user?view=azure-devops#invite-external-user
#     A guest user can add other guest users to the organization after being granted the Guest Inviter role in Microsoft Entra ID.
     param($DevOpsUser, $EntraUser, $GraphToken)

     if ($EntraUser.userType -eq "Guest")
     {
         if ($EntraUser.isGuestInviter -eq $false)
         {
             Write-Host "--------------------------------------------------------------------------------------------"
             Write-Host "Guest User does not have 'Guest Inviter' role in Entra."  -ForegroundColor Red
             Write-Host "Without this role the guest user cannot invite other guest users to the Azure DevOps org."
             
             $response = Read-Host "Would you like to attempt to add the Guest Inviter role to this user? (Y/N)"
             if ($response -eq 'Y' -or $response -eq 'y') {
                 Add-GuestInviterRole -GraphToken $GraphToken -UserId $EntraUser.id
             }
             else {
                 Write-Host "If you are experiencing issues inviting other guest users please assign the 'Guest Inviter'" 
                 Write-Host "role to this user in Entra."
             }
             Write-Host "--------------------------------------------------------------------------------------------"
         }
         else
         {
             Write-Host "Guest User has 'Guest Inviter' role in Entra." -ForegroundColor Green
         }
     }
     else
     {
         Write-Host "Not a Guest User, skipping Guest Role check." -ForegroundColor Green
     }
}

# ===========================
# Function: Compare-GuestInfo
# ===========================
function Compare-GuestInfo {
    param($DevOpsUser, $EntraUser)
    $upn = $EntraUser.userPrincipalName
    
    if ($EntraUser.userType -eq "Guest")  
    {
        
        if ($upn -like "*#EXT#*") 
        {
            #Write-Host "External user detected, converting UPN format" -ForegroundColor DarkGray
            #Write-Host "Entra UPN     : $upn" -ForegroundColor  DarkGray
            $upnParts = $upn -split "#EXT#"
            $localPart = $upnParts[0].Replace("_", "@")
            $upn = $localPart
            #Write-Host "Effective UPN : $upn" -ForegroundColor DarkGray
        }
        if ($upn -cne $EntraUser.mail)
        {
            Write-Host "--------------------------------------------------------------------------------------------"
            Write-Host "Guest User Email and UPN mismatch detected: " -ForegroundColor Red
            Write-Host "UPN   = '$($upn)' " -ForegroundColor Red
            Write-Host " vs" -ForegroundColor Red
            Write-Host "Email = '$($EntraUser.mail)'"  -ForegroundColor Red
            Write-Host "This can cause issues with login, authorization, and access to resources."
            Write-Host "If you are experiencing issues please:" 
            Write-Host "  - Remove the Devops user"
            Write-Host "  - Remove the guest user from Entra"
            Write-Host "  - Re-invite the User to the Entra Tenant (should be new OID)"
            Write-Host "  - Ensure that the new user's UPN is correct, the email is blank or The same as the UPN"
            Write-Host "  - Add the new user to DevOps"
            Write-Host "  "
            Write-Host "If you are still experiencing issues please open a support case with Microsoft and include" 
            Write-Host "this output."
            Write-Host "--------------------------------------------------------------------------------------------"
        }
    }
    else
    {
        Write-Host "Not a Guest User, skipping Entra Guest Info check." -ForegroundColor Green
    }
}

# ===========================
# Main Script
# ===========================
try 
{
    Test-Prerequisites -ForceLogout:$ForceLogout
    #Clear-Host
    $OrgName = Read-Host "Enter Azure DevOps Organization Name"
    $tokens = Get-AccessTokens
    $upn = Read-Host "Enter UPN to check"
    Write-Host "--------------------------------------------------------------------------------------------"
    Write-Host "Logged in User Info:"
    Write-Host "--------------------------------------------------------------------------------------------"
    Write-Host "Logged into Entra as        : $($tokens.Graph.UserId)"
    Write-Host "Logged into Azure DevOps as : $($tokens.DevOps.UserId)"
    Write-Host
    Write-Host "--------------------------------------------------------------------------------------------"
    Write-Host "Entra and Entra User Info:"
    Write-Host "--------------------------------------------------------------------------------------------"
    $tenantInfo = Get-TenantInfo -GraphToken $tokens.Graph
    Write-Host "Entra Tenant Name           : $($tenantInfo.displayName)"
    Write-Host "Entra Tenant ID             : $($tenantInfo.Id)"
    $entraUser = Get-EntraUserInfo -GraphToken $tokens.Graph -UserPrincipalName $upn
    Write-Host "Entra User Principal Name   : $($entraUser.userPrincipalName)"
    Write-Host "Entra User Email            : $($entraUser.mail)"
    Write-Host "Entra User OID              : $($entraUser.id)"
    Write-Host "Entra User Type             : $($entraUser.userType)"
    Write-Host "Entra User State            : $($null -eq $entraUser.externalUserState ? "Internal" : "External - $($entraUser.externalUserState)")"
    Write-Host "Entra User is Guest Inviter : $($entraUser.isGuestInviter)"
    Write-Host
    Write-Host "--------------------------------------------------------------------------------------------"
    Write-Host "Azure DevOps User Info:                                                                     "
    Write-Host "--------------------------------------------------------------------------------------------"
    $devOpsUser = Get-DevOpsUserInfo -OrgName $OrgName -DevOpsToken $tokens.DevOps -UserPrincipalName $upn
    Write-Host "Devops User VSID            : $($devOpsUser.id)"
    Write-Host "Devops User Tenant ID       : $($devOpsUser.properties.Domain."`$value")"
    Write-Host "DevOps User Account Name    : $($devOpsUser.properties.Account."`$value")"
    Write-Host "DevOps User Email           : $($devOpsUser.properties.Mail."`$value")"
    Write-Host "DevOps User OID             : $($devOpsUser.properties."http://schemas.microsoft.com/identity/claims/objectidentifier"."`$value")"
    Write-Host "DevOps User Type            : $($devOpsUser.properties.metaTypeId -eq 1 ? "Guest" :  ($devOpsUser.properties.metaTypeId -eq 0 ? "Unknown" : "Member"))"
    Write-Host
    Write-Host "--------------------------------------------------------------------------------------------"
    Write-Host "DevOps User License Info:                                                                     "
    Write-Host "--------------------------------------------------------------------------------------------"
    $devLicense = Get-DevOpsUserLicense -OrgName $OrgName -DevOpsToken $tokens.DevOps -UserId $devOpsUser.id
    if ($null -ne $devLicense.accessLevel) {
        $alc = $devLicense.accessLevel
        Write-Host "Licensing Source            : $($alc.licensingSource)"
        #Write-Host "License type                : $($alc.accountLicenseType)"
        write-Host "License Display Name        : $($alc.licenseDisplayName)"
        #Write-Host "Assignment Source           : $($alc.assignmentSource)"
        if ($alc.status -ne "active") {
            Write-Host "DevOps User License Status  : $($alc.status)"
            Write-Host "            Status Message  : $($alc.statusMessage) "
        }
        write-Host "Last Accessed Date          : $([System.TimeZoneInfo]::ConvertTime($devLicense.lastAccessedDate, [System.TimeZoneInfo]::Utc, [System.TimeZoneInfo]::Local))"
    }
    else {
        Write-Host "DevOps User License        : Not found or unavailable" -ForegroundColor Yellow
    }
    Write-Host
    Write-Host "--------------------------------------------------------------------------------------------"
    Write-Host "Checking for Known Scenarios..."
    Write-Host "--------------------------------------------------------------------------------------------"
    Compare-Casing     -DevOpsUser $devOpsUser -EntraUser $entraUser -GraphToken $tokens.Graph
    Compare-OID        -DevOpsUser $devOpsUser -EntraUser $entraUser
    Compare-TenantId   -DevOpsUser $devOpsUser -TenantId  $tenantInfo
    Compare-UserType   -DevOpsUser $devOpsUser -EntraUser $entraUser
    Compare-GuestRoles -DevOpsUser $devOpsUser -EntraUser $entraUser -GraphToken $tokens.Graph
    Compare-GuestInfo  -DevOpsUser $devOpsUser -EntraUser $entraUser
    Write-Host
    Write-Host
}
catch {
    $caught = $_.ToString()
    Write-Host "An error occurred: `r`n$($caught)" -ForegroundColor Red
    Write-Host
    Write-Host "Please verify that you are logged in with the correct account that has access to both Entra and Azure DevOps." -ForegroundColor Yellow
    Write-Host "You can try running the script again with the -ForceLogout parameter to clear cached credentials." -ForegroundColor Yellow
    Write-Host
}



