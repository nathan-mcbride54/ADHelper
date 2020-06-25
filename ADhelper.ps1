# ===================================================================================
# Name: ADhelper.ps1
# 
# Purpose: This script was designed to simplify the following tasks.
#   ~ Show all locked out user accounts
#   ~ Unlock a user account by name
#   ~ Compare two user acconts for differences
#   ~ Show users who changed their password in the last 30 days
#   ~ Show users whose password will expire in the next 30 days
#
# Locked Accounts
#   ~ ShowLocked
#   ~ UnlockUser
#
# Password Management
#   ~ PasswordCheck - Next to Expire
#   ~ PasswordCheck - Last Changed
#   ~ ResetPassword
#
# Compare AD Users
#   ~ ShowUserProperties ?
#   ~ CompareAccounts
#
# ================================

# =======================
# Global Variables
# =======================

# Create choice description objects representing valid options and store them in an array for later access.
$LockedAccounts = New-Object System.Management.Automation.Host.ChoiceDescription '&Locked Accounts', 'Show accounts that are locked and unlock them.'
$PasswordCheck = New-Object System.Management.Automation.Host.ChoiceDescription '&Password Check', 'Show passwords last changed and next to expire as well as reset.'
$CompareADUsers =  New-Object System.Management.Automation.Host.ChoiceDescription '&Compare ADUsers', 'Compare properties of AD User accounts.'
$Quit = New-Object System.Management.Automation.Host.ChoiceDescription '&Quit', 'Exit the script.'
$MainMenuOptions = [System.Management.Automation.Host.ChoiceDescription[]]($LockedAccounts, $PasswordCheck, $CompareADUsers, $Quit)

$NextExpire = New-Object System.Management.Automation.Host.ChoiceDescription '&Next To Expire', 'Show the users whose passwords will expire in the next 30 days.'
$LastChanged = New-Object System.Management.Automation.Host.ChoiceDescription '&Last Changed', 'Show the users whose passwords changed in the last 30 days.'
$ResetPassword = New-Object System.Management.Automation.Host.ChoiceDescription '&Reset Password', 'Reset a specified users password.'
$PasswordOptions = [System.Management.Automation.Host.ChoiceDescription[]]($NextExpire, $LastChanged, $ResetPassword)

$Yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'I sure would!'
$No = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No thanks.'
$YesOrNo = [System.Management.Automation.Host.ChoiceDescription[]]($Yes, $No)

# ===============================================================
# Name: Authenticate
# Description: Creates and returns a PSCredential object 
#              if valid Domain Admin credentials are entered.
# Parameters: None.
# Usage: [PSCredential] $Credential = Authenticate
# ===============================================================
Function Authenticate {
    
    Begin {
        $Credential = $host.ui.PromptForCredential("", "Please enter your Domain Admin credentials.", "", "NetBiosUserName")

        Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`nPSBoundParameters: $($PSBoundParameters | Out-String)"
        
        Try { Add-Type -AssemblyName System.DirectoryServices.AccountManagement } 
        Catch { Throw "Could not load assembly: $_" }

        $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::'Domain', 'cronos.local')
    }

    Process {
        If($DS.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().password)) {
            write-host "    Authentication Sucessful!" -ForegroundColor Green
        }
        Else {
            write-host "Authentication failed - please verify your username and password." -ForegroundColor Red
            $DS.Dispose()
            Exit
        }
    }

    End {
        $DS.Dispose()
        Return $Credential
    }
}

# ======================================================================
# Name: ShowHeader
# Description: Displays a header containing the page title for style :)
# Parameters: Title to be displayed in the header.
# Usage: ShowHeader(" Page Title ")
# ======================================================================
Function ShowHeader {
    
    Param ( 
        [String] $Title 
    )

    Begin {
        # Set the width of the console window.
        $Width = $Host.UI.RawUI.WindowSize.Width
        
        # Location to start printing title (Middle of the screen, minus half the length of the title).
        $StartTitle = [Math]::Floor((($Width / 2) - ($Title.length / 2))) 
    }

    Process {
        Write-Host "`n"

        # Loop for the entire width of the console.
        For($Index = 0; $Index -lt $Width; $Index++) {

            # Enough '=' printed, start printing the title.
            If($Index -eq $StartTitle ) {

                Write-Host $Title -NoNewline -ForegroundColor Green

                # Move the index after the title and continue printing.
                $Index = $Index + $Title.length
            }
            Write-Host -NoNewline "="
        }
        Write-Host "`n"
    }
}

# ===============================================================
# Name: ShowLocked
# Description: Print all accounts listed as lockedOut in AD, 
#              returns $False if no accounts lockedOut.
# Parameters: Credential to authorize search for locked ADAccounts.
# Usage: ShowLocked -Credential $Credential
# ===============================================================
Function ShowLocked {

    Param ( 
        [PSCredential] $Credential
    )
    
    # Save any locked accounts to an object.
    $LockedAccounts = (Search-ADAccount -LockedOut -Credential $Credential)

    # Will be true if any locked accounts were found.
    If($LockedAccounts) {

        # Output the locked accounts to the user.
        Write-Output $LockedAccounts | Format-Table -Property Name, LockedOut, LastLogonDate -AutoSize | Out-Host
        Return $True
    }

    # No accounts were found locked.
    Else {
        Write-Host "    No Accounts locked!" -NoNewline -ForegroundColor Green
        Return $False
    }
}

# ===============================================================
# Name: UnlockUser
# Description: Unlock a specified users account if LockedOut.
# Parameters: UserName of the account to unlock and the Credential
#             to authorize the unlock.
# Usage: UnlockUser -UserName $UserName -Credential $Credential
# ===============================================================
Function UnlockUser {
    
    Param ( 
        [PSCredential] $Credential, 
        [String] $UserName 
    )

    Try {
        # Search for a locked out account matching the name provided by the user.
        $Locked = Search-ADAccount -LockedOut | Where-Object {$_.SamAccountName -match $UserName}

        # If the account is found, unlock it.
        if(($Lcoked)) {
            Unlock-ADAccount -Identity $UserName -Credential $Credential
            Write-Host $Locked.SamAccountName " $UserName Unlocked Sucessfuly" -ForegroundColor Green
        }
        # Account was not locked out.
        Else { Write-Host " $UserName is not locked out..." -ForegroundColor Red }
    }
    # A fatal error may have occured.
    Catch { Write-Output $_ }
}

# ====================================================================
# Name: CompareAccounts
# Description: Compare the properties of two ADUser Accounts.
#              Print the property in Green if they Match, Red if not.
# Parameters: Credential to authorize commands.
# Usage: CompareAccounts -Credential $Credential
# ====================================================================
Function CompareAccounts {

    # Check this link for a helpful list of user properties.
    # https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx
    
    Param (
        [PSCredential] $Credential
    )

    $Usercomparison = @() # Hash table to store results.

    Write-Host "`n Enter the first account to compare firstname.lastname"
    $FirstUser = Read-Host "`n >>>"

    Write-Host "`n Enter the second account to compare firstname.lastname"
    $SecondUser = Read-Host "`n >>>"

    # Save all user properties to variables.
    $ADUser1 = Get-ADUser $FirstUser -Properties * -Credential $Credential
    $ADUser2 = Get-ADUser $SecondUser -Properties * -Credential $Credential

    # Iterate through each property of the first user, comparing to the second user.
    $ADUser1.GetEnumerator() | ForEach-Object {

        # If the properties match set to True.
        If ($ADUser2.($_.Key) -eq $_.Value) { 
            [Bool]$Match = $True 
        } Else { 
            [Bool]$Match = $False
        }

        # Create a new object to store the comparison for that property.
        $UserObj = New-Object PSObject -Property ( [ordered] @{
            Property = $_.Key
            User1 = $_.Value
            User2 = $ADUser2.($_.Key)
            Match = $Match
        })
        $UserComparison += $UserObj # Add that object to the hash table.
    }

    # Print the results of the comparison.
    For($Index = 0; $Index -lt $Usercomparison.length; $Index ++) {
        If($Usercomparison[$index].Match) {
            Write-Host $Usercomparison[$index].Property -ForegroundColor Green
        }
        Else {
            Write-Host $Usercomparison[$index].Property -ForegroundColor Red
        }
    }
}

# ========================================================================================
# Name: ResetPassword
# Description: Reset a specified users password.
# Parameters: UserName of the account that requires the reset, the Credential to authorize
#             the reset, and a bool representing if the password should change next logon.
# Usage: ResetPassword -Credential $Credential -UserName $UserName -ChangeAtLogon $True
# ========================================================================================
Function ResetPassword {

    Param ( 
        [PSCredential] $Credential, 
        [String] $UserName,
        [Bool] $ChangeAtLogon
    )

    Try { 
        # Check if $UserName is an AD Account.
        If((Get-ADUser $UserName)) {
            $Password = (Read-Host -Prompt "`n Provide New Password" -AsSecureString)
            Set-ADAccountPassword -Identity $UserName -NewPassword $Password -Reset -Credential $Credential
            Set-ADuser -Identity $UserName -ChangePasswordAtLogon $ChangeAtLogon -Credential $Credential
            Return $True
        } 
        # Account with $UserName does not exist or Get-ADUser threw an error.
        Else {
            Write-Host "No account found matching " $UserName
            Return $False
        }
    }
    # A fatal error may have occured.
    Catch { Write-Output $_ }
}

# ======================================================================
# Name: PasswordCheck
# Description: Lists the users whose password has been changed in
#              the past 30 days or will expire in the next 30.
# Parameters: Credential to authorize and a string to switch the mode.
# Usage: PasswordCheck -Credential $Credential -Mode "NextExpire"
# ======================================================================
Function PasswordCheck {
    
    Param ( 
        [PSCredential] $Credential, 
        [String] $Mode 
    )

    $AccountList = @() # Hash table to store all accounts expiring in next 30 days.

    # DateTime Object for comparison to accounts set to 'Never Expire'.
    $NeverExpires = (Get-date -Year 1600 -Month 12 -Day 31 -Hour 19 -Minute 0 -Second 0)

    # Search for the expiry date for each account and save to a variable.
    $Accounts = (Get-ADUser -Credential $Credential -filter { Enabled -eq $True -and PasswordNeverExpires -eq $False } –Properties "DisplayName", "msDS-UserPasswordExpiryTimeComputed" |
    Select-Object -Property "DisplayName", @{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}})

    # Iterate through the list of all accounts.
    $Accounts | ForEach-Object {

        $CurrentAccount = $_

        # This checks if the account is set to Never Expire (Date would be set to 1600-12-31).
        If($_."ExpiryDate" -gt $NeverExpires) {

            # Calculate the time remaining between now and the expiry.
            $TimeRemaining = (New-TimeSpan -End $_.ExpiryDate)

            Switch($Mode) {

                "NextExpire" {
                    # If the password will expire in the next 30 days, save the information to an object.
                    If($TimeRemaining.Days -gt 0 -and $TimeRemaining.Days -le 30) {
                        $ExpireSoon = New-Object PSObject -Property ( [Ordered] @{
                            UserName = $CurrentAccount.DisplayName
                            DaysRemaining = $TimeRemaining.Days
                            ExpiryDate = $CurrentAccount.ExpiryDate
                        })
                        $AccountList += $ExpireSoon # Add the account to the expire list.
                    }
                }

                "LastChanged" {
                    # If the password was changed in the last -30 days, save the information to an object.
                    If($TimeRemaining.Days -le 0 -and $TimeRemaining.Days -ge -30) {
                        $RecentlyChanged = New-Object PSObject -Property ( [Ordered] @{
                            UserName = $CurrentAccount.DisplayName
                            DaysSinceChange = $TimeRemaining.Days
                            ExpiryDate = $CurrentAccount.ExpiryDate
                        })
                        $AccountList += $RecentlyChanged # Add the account to the list.
                    }
                }
            }
        }
    }

    If($Mode -eq "NextExpire") {
        # Print out all the accounts expiring in the next 30 days.
        $AccountList | Sort-Object -Property DaysRemaining | Format-Table -AutoSize
    }

    If($Mode -eq "LastChanged") {
        $AccountList | Sort-Object -Property DaysSinceChange -Descending | Format-Table -AutoSize
    }

}


# =============
# Script Main
# =============

Clear-Host

ShowHeader(" Authentication Required ")

[PSCredential]$Credential = Authenticate

If($Credential) {

    While($True) {

        ShowHeader(" Main Menu ")

        $MainMenuChoice = $host.ui.PromptForChoice('', ' ', $MainMenuOptions, 0)

        Switch ($MainMenuChoice) {
            
            0 { 
                ShowHeader(" Locked Accounts ")
                
                # The Function ShowLocked ruturns true if any accounts are found locked
                $AccountLocked = ShowLocked -Credential $Credential
                
                If ($AccountLocked) {

                    $UnlockChoice = $host.ui.PromptForChoice('Would you like to unlock an account?', ' ', $YesOrNo, 0)

                    Switch($UnlockChoice) {
                        0 {
                            Write-Host "`n Enter the name of the locked account firstname.lastname"
                            $UserName = Read-Host "`n >>>"
                            UnlockUser -Credential $Credential -UserName $UserName
                        }
                        1 { Write-Host "    No Account unlocked...`n" } 
                    }
                }
            }
            1 { 
                $PasswordChoice = $host.ui.PromptForChoice("Show last changed or next to expire?", " ", $PasswordOptions, 0)
                
                Switch($PasswordChoice) {
                    0 { 
                        ShowHeader(" Passwords Next To Expire ")
                        PasswordCheck -Credential $Credential -Mode "NextExpire" 
                    }
                    1 { 
                        ShowHeader(" Passwords Changed Last ")
                        PasswordCheck -Credential $Credential -Mode "LastChanged" 
                    }
                    2 {
                        ShowHeader(" Reset Password ")

                        Write-Host " Enter the account name (firstname.lastname)"
                        $UserName = Read-Host "`n >>>"

                        $ChangeAtLogon = $host.ui.PromptForChoice("Change password upon next logon?", " ", $YesOrNo, 0)
                        
                        Switch($ChangeAtLogon) {
                            0 { $status = ResetPassword -Credential $Credential -UserName $UserName -ChangeAtLogon $True }
                            1 { $status = ResetPassword -Credential $Credential -UserName $UserName -ChangeAtLogon $False}
                        }

                        If($status) {
                            Write-Host "`n  Password Changed Sucessfuly!" -ForegroundColor Green
                        } Else {
                            Write-Host "`n  Error setting new password" -ForegroundColor Red
                        }
                    }
                }
            }
            2 { 
                ShowHeader(" Compare Accounts ")
                CompareAccounts -Credential $Credential
            }
            3 { Exit }
        }
    }
}
