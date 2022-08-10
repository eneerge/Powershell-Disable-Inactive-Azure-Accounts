#  Configure here
###################
$disableAt = 90 # If an account is inactive for this many days, disable it
$sendWarningNoticeAt = 80 # When should users start receiving notice that their account is about to be disabled.

# Users in these groups should not ever expire or receive notices
$excludeGroups = @(
  "xxxx-xxxxx-xxxxxx-xxxx-xxxx" # This is just the ObjectID of a test group.
)


#####################################################################
# Run this first if not installed already (not needed)
#####################################################################
#Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force
#Install-Module AzureAD


#####################################################################
# Start
#####################################################################
$Today=(Get-Date)
$logDir = "logs"
$logFile = "$logDir\UserStatus_$($Today.ToString("yyyy.MM.dd")).txt"

"Process started at $($Today)" | out-file $logFile
"" | out-file -append $logFile


#####################################################################
# Get Microsoft Graph Api Authentication Token
#####################################################################
$clientID = "xxxxxxxx-xxxxx-xxxx-xxxx-xxxxxxxxxxxx"
$tenantName = "yourTenant.onmicrosoft.com"
$clientSecret = "your secret key (dont push this to version control or you lose)"
 
$ReqTokenBody = @{
  Grant_Type    = "client_credentials"
  Scope         = "https://graph.microsoft.com/.default"
  client_Id     = $clientID
  Client_Secret = $clientSecret
} 

# Get Auth Token
$TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody


#####################################################################
# Get Users data from Microsoft Graph Api
#####################################################################
$uri = 'https://graph.microsoft.com/beta/users?$select=displayName,userPrincipalName,otherMails,signInActivity,accountEnabled,createdDateTime,lastPasswordChangeDateTime' # URI for getting users
$Data = while (-not [string]::IsNullOrEmpty($uri)) {
    $apiCall = try {
        Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)"} -Uri $uri -Method Get
    }
    catch {
        $errorMessage = $_ | ConvertFrom-Json
    }
    $uri = $null
    if ($apiCall) {
        $uri = $apiCall.'@odata.nextLink'
        $apiCall
    }
}
$result = ($Data | select-object Value).Value
$Export = $result | select DisplayName,UserPrincipalName,accountEnabled,otherMails,@{Name='lastPasswordChangeDateTime';Expression={[datetime]::Parse($_.lastPasswordChangeDateTime)}},@{Name='createdDateTime';Expression={[datetime]::Parse($_.createdDateTime)}},@{n="LastLoginDate";e={$_.signInActivity.lastSignInDateTime}}

# Format the results into $Users variable
$Users = $Export | select DisplayName,UserPrincipalName,accountEnabled,otherMails,@{Name='lastPasswordChangeDateTime';Expression={[datetime]::Parse($_.lastPasswordChangeDateTime)}},@{Name='createdDateTime';Expression={[datetime]::Parse($_.createdDateTime)}},@{Name='LastLoginDate';Expression={[datetime]::Parse($_.LastLoginDate)}}

#####################################################################
# Get excluded users data from Microsoft Graph Api
#####################################################################
$exclusionData = @()
foreach ($g in $excludeGroups) {
    $excludeGroupsUri = "https://graph.microsoft.com/v1.0/groups/$g/members/microsoft.graph.user/$count" # URI for getting users that are in an excluded group
    $exclusionData += while (-not [string]::IsNullOrEmpty($excludeGroupsUri)) {
        $apiCall = try {
            Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)"} -Uri $excludeGroupsUri -Method Get
        }
        catch {
            $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json
        }
        $uri = $null
        if ($apiCall) {
            $excludeGroupsUri = $apiCall.'@odata.nextLink'
            $apiCall
        }
    }
}
$excludedUsers = ($exclusionData | select-object Value).Value
 
#####################################################################
# Output all user statuses into log (disabled)
#####################################################################
<#"Current user status" | out-file -append $logFile
"-------------------" | out-file -append $logFile
foreach ($u in ($Users | Sort-Object -Property displayName)) {
  "$(($u.displayName.PadRight(30) + " <"+ $u.userPrincipalName + ">").PadRight(65)) Enabled: " + $u.accountEnabled + " Created: " + $u.createdDateTime + " Last Login: " + $u.LastLoginDate | out-file -Append $logFile
}
"" | out-file -append $logFile#>


#####################################################################
# Output the users who will be skipped to the log
#####################################################################
"Users who will be skipped due to being in an excluded group" | out-file -append $logFile
"-----------------------------------------------------------" | out-file -append $logFile
foreach ($u in ($excludedUsers | Get-Unique -AsString | Sort-Object -Property displayName)) {
  "$(($u.displayName.PadRight(30) + " <"+ $u.userPrincipalName + ">").PadRight(65))" | out-file -Append $logFile
}
"" | out-file -append $logFile


#####################################################################
# Loop through each user to determine the action that should be taken
#####################################################################
$usersToDisable = @()
$usersToWarn = @()
foreach ($User in $Users) {
  # skip user if in an exclusion or already disabled
  if ($User.userPrincipalName -in $excludedUsers.userPrincipalName `
      -or $User.accountEnabled -eq $false) {
    continue
  }

  # Get days since last activity
  $TimeSpanLastLogin = $null
  if ($User.LastLoginDate -eq $null) {
    $TimeSpanLastLogin = New-TimeSpan -Start $User.lastPasswordChangeDateTime -End $Today
  }
  else {
    $TimeSpanLastLogin = New-TimeSpan -Start $User.LastLoginDate -End $Today
  }
  $TimeSpanPWReset = New-TimeSpan -Start $User.lastPasswordChangeDateTime -End $Today
  $TimeSpanCreation = New-TimeSpan -Start $User.createdDateTime -End $Today

  # User should be expired at this many days
  if ($TimeSpanLastLogin.Days -ge $disableAt -and $TimeSpanPWReset.Days -ge $disableAt) {
    $usersToDisable += $User
  }
  elseif ($TimeSpanLastLogin.Days -ge $sendWarningNoticeAt -and $TimeSpanPWReset.Days -ge $disableAt) {
    $usersToWarn += $User
  }
}

#####################################################################
# Process users to warn and log them
#####################################################################
"Users to warn" | out-file -append $logFile
"----------------" | out-file -append $logFile
foreach ($User in $usersToWarn) {
  $TimeSpan = New-TimeSpan -Start $User.LastLoginDate -End $Today

  # If users logged in before, show the last login date
  if ($User.LastLoginDate -eq $User.createdDateTime) {
    "$(($User.displayName.PadRight(30) + " <"+ $User.userPrincipalName + ">").PadRight(65)) - Account Never Logged Into (Last Password Change Date: $($User.LastLoginDate.ToString("MM/dd/yyyy")) $($TimeSpan.Days) days ago)" | out-file -NoNewline -Append $logFile
  }
  # If user never logged in, show when it was created
  else {
    "$(($User.displayName.PadRight(30) + " <"+ $User.userPrincipalName + ">").PadRight(65)) - Stale Account (Last logon: $($User.LastLoginDate) $($TimeSpan.Days) days ago)" | out-file -NoNewline -Append $logFile
  }
  " --> Warned" | out-file -Append $logFile
}
"" | out-file -append $logFile

#####################################################################
# Process users to disable and disable them
#####################################################################
"Users to disable" | out-file -append $logFile
"----------------" | out-file -append $logFile
foreach ($User in $usersToDisable) {
  $TimeSpan = New-TimeSpan -Start $User.LastLoginDate -End $Today

  # If users logged in before, show the last login date
  if ($User.LastLoginDate -eq $User.createdDateTime) {
    "$(($User.displayName.PadRight(30) + " <"+ $User.userPrincipalName + ">").PadRight(65)) - Account Never Logged Into (Last Password Change Date: $($User.LastLoginDate.ToString("MM/dd/yyyy")) $($TimeSpan.Days) days ago)" | out-file -NoNewline -Append $logFile
  }
  # If user never logged in, show when it was created
  else {
    "$(($User.displayName.PadRight(30) + " <"+ $User.userPrincipalName + ">").PadRight(65)) - Stale Account (Last logon: $($User.LastLoginDate) $($TimeSpan.Days) days ago)" | out-file -NoNewline -Append $logFile
  }

  #### Do the disablement
  $uri = "https://graph.microsoft.com/v1.0/users/$($User.userPrincipalName)"

  # @odata.nextLink is used if results greated than 999 results
  $Data = while (-not [string]::IsNullOrEmpty($uri)) {
    $apiCall = try {
      Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)"} -Uri $uri -Method Patch -ContentType 'application/json' -Body '{"accountEnabled":"false"}'
      " --> Account Disabled".PadLeft(15) | out-file -NoNewLine -Append $logFile
    } catch {
      # Log any errors
      "Error: " | out-file -NoNewLine -Append $logFile
      $_ | out-file -Append $logFile
    }
    $uri = $null
    if ($apiCall) {
      $uri = $apiCall.'@odata.nextLink'
      $apiCall
    }
  }

  "" | out-file -Append $logFile
  sleep -Milliseconds 500
}

#####################################################################
# Send notifications of warning and disablement
#####################################################################
$emailTemplate = @"
  <style>
    .ExternalClass * { line-height:22px; }
  </style>
  <table border="0" cellpadding="0" cellspacing="0" width="100%">
      <tr>
          <td>
              <table border="0" cellpadding="0" cellspacing="0" width="640" align="center">
                  <tr>
                      <td align="center"><a href="https://edit.this.domain.com"><img src="https://edit.this.domain.com/logo.png" width="263" height="100" border="0" /></a></td>
                  </tr>
                  <tr>
                      <td style="padding:25px; text-align:center;" valign="top">
                          <h1 style="font-size: 26px;color:#00245c;font-family: Arial, Helvetica, sans-serif">[!title!]</h1>
                      </td>
                  </tr>
                  <tr>
                      <td>
                          <div style="border-bottom: #929292 solid 2px">
                              <img src="https://images.e2ma.net/images/spacer.gif" style="display:block" width="1" height="1" border="0">
                          </div>
                      </td>
                  </tr>
                  <tr>
                      <td align="left" style="padding:30px 40px 30px 40px; text-align:left;" valign="top">
                          <span style="font-size: 26px;color:#00245c;font-family: Arial, Helvetica, sans-serif; font-weight:normal;">[!subtitle!]</span>
                      </td>
                  </tr>
                  <tr>
                      <td align="left" valign="top" style="padding:0px 40px 0px 40px; mso-line-height-rule: exactly; line-height:22px;">
                          <span style="font-family:Arial, Helvetica, sans-serif; vertical-align: baseline; font-size: 14px; color: #333333;mso-line-height-rule: exactly; line-height: 22px;;">[!body!]</span>
                      </td>
                  </tr>
                  <tr>
                      <td height="12">
                          &nbsp;
                      </td>
                  </tr>
                  <tr>
                      <td align="left" valign="top" style="padding:0px 40px 0px 40px; mso-line-height-rule: exactly; line-height: 22px;">
                          <span style="font-family:Arial, Helvetica, sans-serif; vertical-align: baseline; font-size: 14px; color: #333333;mso-line-height-rule: exactly; line-height: 22px;"><strong>Your account:</strong> [!userPrincipalName!]</span>
                      </td>
                  </tr>
                  <tr>
                      <td align="left" valign="top" style="padding:0px 40px 0px 40px; mso-line-height-rule: exactly; line-height: 22px;">
                          <span style="font-family:Arial, Helvetica, sans-serif; vertical-align: baseline; font-size: 14px; color: #333333;mso-line-height-rule: exactly; line-height: 22px;"><strong>Last activity:</strong> &nbsp; [!lastActivity!]</span>
                      </td>
                  </tr>
                  <tr>
                      <td height="12">
                          &nbsp;
                      </td>
                  </tr>
                  <tr>
                      <td align="left" valign="top" style="padding:0px 40px 0px 40px; mso-line-height-rule: exactly; line-height: 22px;">
                          <span style="font-family:Arial, Helvetica, sans-serif; vertical-align: baseline; font-size: 14px; color: #333333;mso-line-height-rule: exactly; line-height: 22px;">[!bodyClosing!]</span>
                      </td>
                  </tr>
                  <tr>
                      <td height="30">
                          &nbsp;
                      </td>
                  </tr>
                  <tr>
                      <td>
                          <div style="border-bottom: #929292 solid 2px">
                              <img src="https://images.e2ma.net/images/spacer.gif" style="display:block" width="1" height="1" border="0">
                          </div>
                      </td>
                  </tr>
                  <tr>
                      <td height="12">
                          &nbsp;
                      </td>
                  </tr>
                  <tr>
                      <td align="center">
                        <span style="font-family:Arial, Helvetica, sans-serif; vertical-align: baseline; font-size: 14px; color: #333333;mso-line-height-rule: exactly; line-height: 22px;">This email was sent to: [!to!]</span>
                      </td>
                  </tr>

              </table>
          </td>
      </tr>
  </table>
"@



###################################
#### Send warning notices about expiring accounts
$emailSubject = "Your Account Is About To Expire"
$emailTitle = "Notice of Account Expiration"
$emailSubTitle = "Your Account Is About To Expire"
$emailBody = "Your account will be disabled soon due to inactivity. To help maintain the security of user data, we automatically disable any accounts that appear to be inactive after a period of " + $disableAt + " days. "
$emailBody += "If disabled, you will no longer be able to access our cloud services."
$emailBodyClosing = 'To prevent your account from being disabled, please <a href="https://office.com/login">login</a> soon to keep your account active.'

foreach ($User in $usersToWarn) {
  $to = $User.otherMails
  if ($User.otherMails.Count -eq 0) {
    $to = $User.userPrincipalName
  }

  $emailHtml = $emailTemplate.replace("[!title!]",$emailTitle)
  $emailHtml = $emailHtml.replace("[!subtitle!]",$emailSubTitle)
  $emailHtml = $emailHtml.replace("[!body!]",$emailBody)
  $emailHtml = $emailHtml.replace("[!bodyClosing!]",$emailBodyClosing)  
  $emailHtml = $emailHtml.replace("[!userPrincipalName!]",$User.userPrincipalName)  
  $emailHtml = $emailHtml.replace("[!lastActivity!]",$User.LastLoginDate)
  $emailHtml = $emailHtml.replace("[!to!]",$to)
  try {
    Send-MailMessage `
      -from "automation@edit.this.domain.com" `
      -to $to `
      -subject "$emailSubject" `
      -body "$emailHtml" `
      -bodyAsHtml `
      -smtpServer "edit.this.smtp.server.com"
  }
  catch {
    "Error while sending warning notice to: " + $(($User.displayName.PadRight(30) + " <"+ $User.userPrincipalName + ">").PadRight(65)) | out-file -NoNewline -Append $logFile
    $_ | out-file -Append $logFile
  }
}

###################################
#### Send disablement notices
$emailSubject = "Your Has Been Disabled"
$emailTitle = "Notice of Account Disablement"
$emailSubTitle = "Your Account Has Been Disabled"
$emailBody = "Your account has been disabled due to " + $disableAt + " days or more of inactivity. To help maintain the security of user data, we automatically disablee any accounts that appear to be inactive after a period of " + $disableAt + " days."
$emailBody += "<br><br>You will no longer be able to access our cloud services."
$emailBodyClosing = 'To re-enable your account, please send a support request to <a href="mailto:support@edit.this.domain.com">support@edit.this.domain.com</a>.'

foreach ($User in $usersToDisable) {
  $to = $User.otherMails
  if ($User.otherMails.Count -eq 0) {
    $to = $User.userPrincipalName
  }

  $emailHtml = $emailTemplate.replace("[!title!]",$emailTitle)
  $emailHtml = $emailHtml.replace("[!subtitle!]",$emailSubTitle)
  $emailHtml = $emailHtml.replace("[!body!]",$emailBody)
  $emailHtml = $emailHtml.replace("[!bodyClosing!]",$emailBodyClosing)  
  $emailHtml = $emailHtml.replace("[!userPrincipalName!]",$User.userPrincipalName)  
  $emailHtml = $emailHtml.replace("[!lastActivity!]",$User.LastLoginDate)
  $emailHtml = $emailHtml.replace("[!to!]",$to)
  try {
      -from "automation@edit.this.domain.com" `
      -to $to `
      -subject "$emailSubject" `
      -body "$emailHtml" `
      -bodyAsHtml `
      -smtpServer "edit.this.smtp.server.com"
  }
  catch {
    "Error while sending disablement notice to: " + $(($User.displayName.PadRight(30) + " <"+ $User.userPrincipalName + ">").PadRight(65)) | out-file -NoNewline -Append $logFile
    $_ | out-file -Append $logFile
  }
}


####################################################################
## Send a list of the users that were warned or disabled to security
####################################################################
$usersToDisable | select-object displayName,userPrincipalName,accountEnabled,@{Name="otherMails";Expression={$_.otherMails -join ';'}},lastPasswordChangeDateTime,createdDateTime,LastLoginDate | Export-Csv -NoTypeInformation -LiteralPath "$logDir\UsersDisabled_$($Today.ToString("yyyy.MM.dd")).csv"
$usersToWarn | select-object displayName,userPrincipalName,accountEnabled,@{Name="otherMails";Expression={$_.otherMails -join ';'}},lastPasswordChangeDateTime,createdDateTime,LastLoginDate | Export-Csv -NoTypeInformation -LiteralPath "$logDir\UsersWarned_$($Today.ToString("yyyy.MM.dd")).csv"

$subject = "Daily Azure User Audit Report"
$body = "Today's Azure user audit reports have been attached."
Send-MailMessage `
  -from "automation@edit.this.domain.com" `
  -to "security@edit.this.domain.com" `
  -subject "$subject" `
  -body "$body" `
  -bodyAsHtml `
  -Attachments @("$logDir\UsersDisabled_$($Today.ToString("yyyy.MM.dd")).csv","$logDir\UsersWarned_$($Today.ToString("yyyy.MM.dd")).csv") `
  -smtpServer "edit.this.smtp.server.com"
