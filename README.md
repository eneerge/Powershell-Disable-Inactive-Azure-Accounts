# Powershell-Disable-Inactive-Azure-Accounts

This Powershell script can be scheduled to run daily to warn and/or disable users in an Azure tenant who have not logged on in a certain period of time.

If a user has an alternate email configured, the warning email and the disablement email will be sent to the alternate email. If no alternate email is configured on the user's account, it will be sent to their Azure account. In the case of the warning email, this is fine. However, you have a catch-22 if the disablement email is sent to the Azure account - they won't see it because they won't be able to login to get the email.

To avoid the catch-22 situation, I recommend your Azure users have an alternate email configured on their account so they will receive both the warning notice and the disablement notice.

## How to Use
This script utilizes Microsoft Graph Api calls. To make these calls, you must set up an App Registration in Azure Portal.
- Create a new app
  - Go to https://portal.azure.com and login
  - Go to Azure Active Directory
  - Go to "App registrations"
  - Click "New registration"
  - Name the app whatever you want it to be. EG: Disable Azure User Accounts
  - Leave the single tenant option selected
  - You can leave redirect URI blank.
  - Click "Register"

- Configure the new app
  - Open the app settings
  - Go to "certificates & secrets"
  - Click "New client secret" and record the value in a safe place for use later
  - Click on "API Permissions"
  - Add the following permissions (Microsoft Graph Api -> Application permissions):
    - AuditLog.Read.All
    - Directory.Read.All
    - User.ManageIdentities.All
    - User.ReadWrite.All
  - Click "Grant admin consent for <tenant>" which appears above the permissions
  
- Configure the Powershell script
  - Open the script 
  - Configure $disableAt and $sendWarningNoticeAt
  - Configure $excludeGroups if you would like to exclude a subset of users from ever being deactivated. This is the "ObjectID" of the group when you view it in Azure.
  - Configure $logDir to a folder that already exists
  - Under "# Get Microsoft Graph Api Authenticaiton Token section"
    - For $clientId, enter the application (client) id of the app you created in the preceeding steps
    - For $tenantName, enter your account.onmicrosoft.com tenant
    - For $clientSecret, enter the client secret you created in the preceeding steps
    - NEVER PUBLISH THE ABOVE TENANT INFORMATION!
    - Don't push this script into any version control, because the secrets configured inside the script will allow anyone to control all users in your tenant.
  - Configure the $emailTemplate with your logo / theme (emailTemplate is near the bottom of the script)
  - Configure the $emailSubject, title, etc
  - Configure the smtp server used to send the notifications (Optional: Set up SPF record for the server that will be running this script in your domain's DNS to prevent notices getting sent to spam)
  - If you would like csv files of all users notified/disabled emailed to someone, that can be configured at the bottom
  
  
# Notes
If you see any security related issues, please let me know ASAP by creating an "issue". I may add additional support for "certificate" authentication later.

You shouldn't need to install the Az or AzureAD powershell modules. I was testing using those modules at first, but I don't think they are needed.

When reactivating a user's account, be sure to also reset their password at the same time. By resetting the password, you can prevent the account from being re-disabled when the script is run again - the last password reset date is considered when warning/disabling accounts.
