# ===================================================================================
# Name: ADhelper.ps1
# 
# Purpose: This script was designed to simplify the following tasks.
#   - Show all locked out user accounts
#   - Unlock a user account by name
#   - Compare two user acconts for differences
#   - Show users who changed their password in the last 30 days
#   - Show users whose password will expire in the next 30 days
#
# Functions:
# Locked Accounts
# - showLocked
# - unlockUser
#
# Password Management
# - passwordExpiryCheck
# - passwordLastChanged
# - resetPassword
#
# Compare AD Users
# - showSingleUser
# - compareTwoUsers
#
# ================================


# Creates and returns a credential if valid Domain Admin credentials are provided
Function Authenticate() {
    
    Begin {
        $Credential = $host.ui.PromptForCredential("", "Please enter your Domain Admin credentials.", "", "NetBiosUserName")

        Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`nPSBoundParameters: $($PSBoundParameters | Out-String)"
        
        Try { Add-Type -AssemblyName System.DirectoryServices.AccountManagement } 
        Catch { Throw "Could not load assembly: $_" }

        $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::'Domain', 'cronos.local')
    }

    Process {
        If($DS.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().password)) {
            write-host "Authentication Sucessful" -ForegroundColor Green
        }
        Else {
            write-host "Authentication failed - please verify your username and password." -ForegroundColor Red
            Exit
        }
    }

    End {
        $DS.Dispose()
        Return $Credential
    }
}

# Displays a header containing the page title for style
Function showHeader {
    
    Param ( 
        [String] $Title 
    )

    Begin {
        $Width = $Host.UI.RawUI.WindowSize.Width # Set the width of the console window
        $StartTitle = [Math]::Floor((($Width / 2) - ($Title.length / 2))) # Location to start printing title
    }

    Process {
        Write-Host "`n"
        For($Index = 0; $Index -lt $Width; $Index++) {
            If($Index -eq $StartTitle ) {
                Write-Host $Title -NoNewline -ForegroundColor Green
                $Index = $Index + $Title.length
            }
            Write-Host -NoNewline "="
        }
        Write-Host "`n"
    }
}

# Print all accounts listed as locked
Function showLocked {

    Param ( 
        [PSCredential] $Credential
    )
    
    $LockedAccounts = (Search-ADAccount -LockedOut -Credential $Credential | Format-Table -Property "Name", "LockedOut", "LastLogonDate")

    If($LockedAccounts) {
        $LockedAccounts | Format-Table -Property "Name", "LockedOut", "LastLogonDate" -AutoSize
        Return $True
    }
    Else {
        Write-Host "    No Accounts locked!" -NoNewline -ForegroundColor Green
        Return $False
    }
}

# Unlock a specified users account
Function unlockUser {
    
    Param ( 
        [PSCredential] $Authorization, 
        [String] $UserName 
    )

    # Locate the requrested AD account using DA credentials and save to variable
    If($ADaccount = Get-ADUser -Credential $Authorization -Identity $UserName.ToString()) {
        
        # If the account is found locked, unlock it
        If($ADaccount.LockedOut -eq $True) {
            Unlock-ADAccount -Identity $ADaccount -Credential $Authorization
            Write-Host $ADaccount.SamAccountName "unlocked sucessfuly" -ForegroundColor Green
        }

        # Account was not locked out
        Else { Write-Host "$UserName is not locked out..." -ForegroundColor Red }
    }

    # Account did not exist
    Else { Write-Host "An account $UserName was not found..." -ForegroundColor Red }
}

Function compareAccounts {

    # https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx
    
    Param (
        [PSCredential] $Credential
    )

    $Usercomparison = @() # Hash table to store results

    Write-Host "Enter the first account to compare firstname.lastname"
    $FirstUser = Read-Host ">>>"

    Write-Host "Enter the second account to compare firstname.lastname"
    $SecondUser = Read-Host ">>>"

    # Save all user properties to variables 
    $ADUser1 = Get-ADUser $FirstUser -Properties * -Credential $Credential
    $ADUser2 = Get-ADUser $SecondUser -Properties * -Credential $Credential

    # Iterate through each property of the first user, comparing to the second user
    $ADUser1.GetEnumerator() | ForEach-Object {

        # If the properties match set to True
        If ($ADUser2.($_.Key) -eq $_.Value) { 
            [Bool]$Match = $True 
        } Else { 
            [Bool]$Match = $False
        }

        # Create a new object to store the comparison for that property
        $UserObj = New-Object PSObject -Property ( [ordered] @{
            Property = $_.Key
            User1 = $_.Value
            User2 = $ADUser2.($_.Key)
            Match = $Match
        })
        $UserComparison += $UserObj # Add that object to the hash table
    }

    # Print the results of the comparison
    For($Index = 0; $Index -lt $Usercomparison.length; $Index ++) {
        If($Usercomparison[$index].Match) {
            Write-Host $Usercomparison[$index].Property -ForegroundColor Green
        }
        Else {
            Write-Host $Usercomparison[$index].Property -ForegroundColor Red
        }
    }
}

Function resetPassword {

    Param ( 
        [PSCredential] $Credential, 
        [String] $UserName,
        [Bool] $ChangeAtLogon
    )

	If((Get-ADUser $UserName)) {
        $Password = (Read-Host -Prompt "Provide New Password" -AsSecureString)
		Set-ADAccountPassword -Identity $UserName -NewPassword $Password -Reset -Force -Credential $Credential
		Set-ADuser -Identity $UserName -ChangePasswordAtLogon $ChangeAtLogon -Credential $Credential
    }
    Else {
        Write-Host "No account found matching " $UserName
    }
}

Function passwordCheck {
    
    Param ( 
        [PSCredential] $Credential, 
        [String] $Mode 
    )

    Begin {
        $AccountList = @() # Hash table to store all accounts expiring in next 30 days
        $NeverExpires = (Get-date -Year 1600 -Month 12 -Day 31 -Hour 19 -Minute 0 -Second 0) # DateTime Object for comparison to accounts set to 'Never Expire'
    
        # Search for the expiry date for each account and save to a variable
        $Accounts = (Get-ADUser -Credential $Credential -filter { Enabled -eq $True -and PasswordNeverExpires -eq $False } –Properties "DisplayName", "msDS-UserPasswordExpiryTimeComputed" |
        Select-Object -Property "DisplayName", @{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}})
    }

    Process {
        # Iterate through the list of all accounts
        $Accounts | ForEach-Object {

            $CurrentAccount = $_

            # This checks if the account is set to Never Expire (Date would be set to 1600-12-31)
            If($_."ExpiryDate" -gt $NeverExpires) {
    
                # Calculate the time remaining between now and the expiry
                $TimeRemaining = (New-TimeSpan -End $_.ExpiryDate)

                $Mode = "NextExpire"
                Switch($Mode) {

                    "NextExpire" {
                        # If the password will expire in the next 30 days, save the information to an object
                        If($TimeRemaining.Days -gt 0 -and $TimeRemaining.Days -le 30) {
                            $ExpireSoon = New-Object PSObject -Property ( [Ordered] @{
                                UserName = $CurrentAccount.DisplayName
                                DaysRemaining = $TimeRemaining.Days
                                ExpiryDate = $CurrentAccount.ExpiryDate
                            })
                            $AccountList += $ExpireSoon # Add the account to the expire list
                        }
                    }

                    "LastChanged" {
                        # If the password was changed in the last -30 days, save the information to an object
                        If($TimeRemaining.Days -le 0 -and $TimeRemaining.Days -ge -30) {
                            $RecentlyChanged = New-Object PSObject -Property ( [Ordered] @{
                                UserName = $CurrentAccount.DisplayName
                                DaysRemaining = $TimeRemaining.Days
                                ExpiryDate = $CurrentAccount.ExpiryDate
                            })
                            $AccountList += $RecentlyChanged # Add the account to the list
                        }
                    }
                }
            }
        }
        # Print out all the accounts expiring in the next 30 days
        $AccountList | Sort-Object -Property DaysRemaining | Format-Table -AutoSize
    }
    End { Return $AccountList }
}





# ============================================
#
# SCRIPT MAIN
#
# ============================================

Clear-Host

showHeader(" Authentication Required ")

[PSCredential]$Credential = Authenticate

If($Credential) {

    Clear-Host

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

    While($True) {

        showHeader(" Main Menu ")

        $MainMenuChoice = $host.ui.PromptForChoice('', ' ', $MainMenuOptions, 0)

        Switch ($MainMenuChoice) {
            
            0 { 
                showHeader(" Locked Accounts ")
                
                $AccountLocked = showLocked($Credential)
                
                If ($AccountLocked) {
                    
                    $UnlockChoice = $host.ui.PromptForChoice('Would you like to unlock an account?', ' ', $YesOrNo, 0)
                    
                    Switch($UnlockChoice) {
                        0 {
                            Write-Host " Enter the name of the locked account firstname.lastname"
                            $UserName = Read-Host "`n >>>"

                            unlockUser($Credential, $UserName)
                        }
                        1 { Write-Host "    No Account unlocked...`n" } 
                    }
                }
            }
            1 { 
                $PasswordChoice = $host.ui.PromptForChoice("Show last changed or next to expire?", " ", $PasswordOptions, 0)
                
                Switch($PasswordChoice) {
                    0 { 
                        showHeader("Passwords Next To Expire ")
                        passwordCheck -Credential $Credential -Mode "NextExpire" 
                    }
                    1 { 
                        showHeader(" Passwords Changed Last ")
                        passwordCheck -Credential $Credential -Mode "LastChanged" 
                    }
                    2 {
                        showHeader(" Reset Password ")

                        Write-Host " Enter the account name (firstname.lastname)"
                        $UserName = Read-Host "`n >>>"

                        $ChangeAtLogon = $host.ui.PromptForChoice("Change password upon next logon?", " ", $YesOrNo, 0)
                        
                        Switch($ChangeAtLogon) {
                            0 { resetPassword -Credential $Credential -UserName $UserName -ChangeAtLogon $True }
                            1 { resetPassword -Credential $Credential -UserName $UserName -ChangeAtLogon $False}
                        }
                    }
                }
            }
            2 { 
                showHeader(" Compare Accounts ")
                compareAccounts -Credential $Credential
            }
            3 { Exit }
        }
    }
}
