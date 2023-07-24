Import-Module ActiveDirectory

$Users = Import-Csv -Delimiter "," -Path ".\users.csv"

foreach ($User in $Users) {
  $SAM = $User.Username
  $Displayname = $User.Displayname
  $Firstname = $User.Firstname
  $Lastname = $User.Lastname
  $OU = $User.Container
  $UPN = $User.Username + "@contoso.com"
  $Password = (ConvertTo-SecureString $User.Password -AsPlainText -Force)
  
  New-ADUser -Name "$Displayname" -DisplayName "$Displayname" -SamAccountName "$SAM" -UserPrincipalName "$UPN" -GivenName "$Firstname" -Surname "$Lastname" -AccountPassword $Password -Enabled $true -Path "$OU" -ChangePasswordAtLogon $false -PasswordNeverExpires $true
  
  Write-Host "Created user: $SAM"
}
