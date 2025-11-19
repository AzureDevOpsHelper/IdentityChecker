# ===========================
# Function: Test-Prerequisites
# ===========================
function Test-Prerequisites {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        Clear-Host
        Write-Host "It seems that the Az module is not installed or not working properly."
        Write-Host "Please wait while we attempt to install the Az module."
        Install-Module -Name Az -Repository PSGallery -Force -AllowClobber -Verbose -Scope CurrentUser -ErrorAction Stop
        Clear-Host
        Write-Host "Az module installed successfully."
        Connect-AzAccount -WarningAction 'SilentlyContinue' -ErrorAction 'Stop' -InformationAction 'SilentlyContinue' -ProgressAction 'SilentlyContinue'
    }
#    Write-Host "updating Az module..."
#    Update-PSResource Az -ErrorAction SilentlyContinue 
    #AZ logout 
    #AZ account clear
    #AZ login
    #Get-TenantInfo

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
    $uri = "https://graph.microsoft.com/v1.0/users/$($UserPrincipalName)?`$select=id,userPrincipalName,creationType,externalUserState,displayName,mail"
    $headers = @{
        Authorization           = $GraphToken.AuthHeader
        "X-TFS-FedAuthRedirect" = "Suppress"
        ConsistencyLevel        = "eventual"
    }
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get

    $uri = "https://graph.microsoft.com/v1.0/users/$($response.id)/appRoleAssignments?`$filter=resourceDisplayName eq 'Guest Inviter'"
    $roles = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET
    #write-host $uri
    #write-host $($roles | convertto-Json -depth 10)
    $response | Add-Member -NotePropertyName 'isGuestInviter' -NotePropertyValue (($roles.value.Count -eq 0) ? $false : $true) -Force
    return $response
}

# ===========================
# Function: Compare-Casing
# ===========================
function Compare-Casing {
    param($DevOpsUser, $EntraUser)
    if ($DevOpsUser.properties.Account."`$value" -cne $EntraUser.userPrincipalName) 
    {
        Write-Host "--------------------------------------------------------------------------------------------"
        Write-Host "Casing mismatch detected: DevOps='$($DevOpsUser.properties.Account."`$value")' vs Entra='$($EntraUser.userPrincipalName)'" -ForegroundColor Red
        Write-Host "This can cause issues when attempting to read info from entra such a s groups or users."
        Write-Host "Consider updating the UPN casing in Entra to match DevOps."
        Write-Host "If you are not able to do this you can open a support case with Microsoft to have them"
        Write-Host "update the UPN casing in DevOps to match Entra and include this output."
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
        Write-Host "OID mismatch detected: DevOps='$($DevOpsUser.properties."http://schemas.microsoft.com/identity/claims/objectidentifier"."`$value")' vs Entra='$($EntraUser.id)'"  -ForegroundColor Red
        Write-Host "This can cause issues with login, authorization, and access to resources."
        Write-Host "If you are experiencing issues please open a support case with Microsoft and include this output."
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
        Write-Host "Tenant ID mismatch detected: DevOps='$($DevOpsUser.properties.Domain."`$value")' vs Entra='$($TenantId.Id)'"  -ForegroundColor Red
        Write-Host "This WILL cause issues with login, authorization, and access to resources."
        Write-Host "Please verify that the user is logging in to the user in the correct tenant."
        Write-Host "It can be simpler to see this if you use a private browsing session to login."
        Write-Host "If this does not resolve the issue, please open a support case with Microsoft and include this output."
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
    $entraType = if ($null -eq $EntraUser.externalUserState) { "Member" } else { "Guest" }
    $devopsType = if ($DevOpsUser.properties.metaTypeId -eq 1) { "Guest" } elseif ($DevOpsUser.properties.metaTypeId -eq 0) { "Unknown" } else { "Member" }
    if ($entraType -ne $devopsType) 
    {
        Write-Host "--------------------------------------------------------------------------------------------"
        Write-Host "User Type mismatch detected: DevOps='$devopsType' vs Entra='$entraType'"  -ForegroundColor Red
        Write-Host "This can cause issues with login, authorization, and access to resources."
        Write-Host "If you are experiencing issues please open a support case with Microsoft and include this output."
        Write-Host "--------------------------------------------------------------------------------------------"
    } 
    else 
    {
        Write-Host "User Type matches." -ForegroundColor Green
    }
}

# ===========================
# Function: Compare-GuestRoles
# ===========================
function Compare-GuestRoles 
{
#     https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/add-external-user?view=azure-devops#invite-external-user
#     A guest user can add other guest users to the organization after being granted the Guest Inviter role in Microsoft Entra ID.
     param($DevOpsUser, $EntraUser)

     if ($EntraUser.metaTypeId -eq 1)
     {
         if ($EntraUser.isGuestInviter -eq $false)
         {
             Write-Host "--------------------------------------------------------------------------------------------"
             Write-Host "Guest User does not have 'Guest Inviter' role in Entra."  -ForegroundColor Yellow
             Write-Host "Without this role the guest user cannot invite other guest users to the Azure DevOps organization."
             Write-Host "If you are experiencing issues inviting other guest users please assign the 'Guest Inviter' role to this user in Entra."
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
    if (($EntraUser.metaTypeId -eq 1) -and ($EntraUser.userPrincipalName -cne $EntraUser.mail)) 
    {
        Write-Host "--------------------------------------------------------------------------------------------"
        Write-Host "Guest User Email and UPN mismatch detected: UPN='$($EntraUser.userPrincipalName)' vs Email='$($EntraUser.mail)'"  -ForegroundColor Red
        Write-Host "This can cause issues with login, authorization, and access to resources."
        Write-Host "If you are experiencing issues please:" 
        Write-Host "  - Remove the Devops user"
        Write-Host "  - Remove the guest user from Entra"
        Write-Host "  - Re-invite the User to the Entra Tenant (should be new OID)"
        Write-Host "  - Ensure that the new user's UPN is correct, the email is blank or The same as the UPN"
        Write-Host "  - Add the new user to DevOps"
        Write-Host "  "
        Write-Host "If you are still experiencing issues please open a support case with Microsoft and include this output."
        Write-Host "--------------------------------------------------------------------------------------------"
    }
    else
    {
        Write-Host "Not a Guest User, skipping Entra Guest Info check." -ForegroundColor Green
    }
}

# ===========================
# Main Script
# ===========================
Test-Prerequisites
#Clear-Host
$OrgName = Read-Host "Enter Azure DevOps Organization Name"
$tokens = Get-AccessTokens
$upn = Read-Host "Enter UPN to check"
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
Write-Host "Entra User Type             : $($null -eq $entraUser.externalUserState ? "Member" : "Guest")"
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
    Write-Host "License type                : $($alc.accountLicenseType)"
    write-Host "License Display Name        : $($alc.licenseDisplayName)"
#    Write-Host "Licensing Source            : $($alc.licensingSource)"
#    Write-Host "Assignment Source           : $($alc.assignmentSource)"
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
Compare-Casing     -DevOpsUser $devOpsUser -EntraUser $entraUser
Compare-OID        -DevOpsUser $devOpsUser -EntraUser $entraUser
Compare-TenantId   -DevOpsUser $devOpsUser -TenantId  $tenantInfo
Compare-UserType   -DevOpsUser $devOpsUser -EntraUser $entraUser
Compare-GuestRoles -DevOpsUser $devOpsUser -EntraUser $entraUser
Compare-GuestInfo  -DevOpsUser $devOpsUser -EntraUser $entraUser
Write-Host
Write-Host

# ===========================
# To Dos:
# - Add "is User a guest in Entra, do they have any roles?" 
# - Add "possibly auth failures due to CAP (e.g. IP misconfig where they hit us with multiple IPs, or CAPs apply to IPv4 but not IPv6, etc.)"
# - Add "Member user stuck as a guest on the DevOps side"
# ===========================