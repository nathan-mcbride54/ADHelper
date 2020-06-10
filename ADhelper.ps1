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
# ====================================================================================


# Creates and returns a credential if valid Domain Admin credentials are provided
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

# Prompts the user for an input and wont return unless it's valid
Function grabValidInput {

    Begin { [Bool]$Valid = $False }

    Process {
        While($Valid -eq $False) {
            $Prompt = Read-Host ">>>"
            If($Prompt -lt 4) { $Valid = $True }
            Else { Write-Host "Invalid Input" -ForegroundColor Red }
        }
    }

    End { Return $Prompt }
}

# Displays a header containing the page title for style
Function showHeader {
    
    Param([String]$Title)

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

# Unlock a specified users account
Function unlockUser {
    
    Param( 
        [PSCredential]$Authorization, 
        [String]$UserName 
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
    
    Param(
        [PSCredential]$Authorization, 
        [String]$FirstUser, 
        [String]$SecondUser
    )

    $Usercomparison = @() # Hash table to store results

    # Save all user properties to variables 
    $ADUser1 = Get-ADUser $FirstUser -Properties * -Credential $Authorization
    $ADUser2 = Get-ADUser $SecondUser -Properties * -Credential $Authorization

    # Iterate through each property of the first user, comparing to the second user
    $ADUser1.GetEnumerator() | ForEach-Object {

        # If the properties match set to True
        If ($ADUser2.($_.Key) -eq $_.Value) { 
            $Match = $True 
        } Else { 
            $Match = $False
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
        [PSCredential]$Authorization, 
        [String]$UserName 
    )

	If((Get-ADUser $UserName)) {

        $Password = (Read-Host -Prompt "Provide New Password" -AsSecureString)
		Set-ADAccountPassword -Credential $Authorization -Identity $UserName -NewPassword $Password -Reset -Force
		Set-ADuser $UserName -ChangePasswordAtLogon $True
	}
}

Function passwordExpiryCheck {
    
    Param (
        [PSCredential]$Authorization, 
        [Int64]$DaysUntilExpire, 
        [bool]$ShowExpire
    )

    Begin {
        $LastChange = @() # HAsh table to store the accounts whose passwords were changed last
        $ExpireList = @() # Hash table to store all accounts expiring in next 30 days
        $NeverExpires = (Get-date -Year 1600 -Month 12 -Day 31 -Hour 19 -Minute 0 -Second 0) # DateTime Object for comparison to accounts set to 'Never Expire'
    
        # Search for the expiry date for each account and save to a variable
        $Accounts = (Get-ADUser -Credential $Authorization -filter {
            Enabled -eq $True -and 
            PasswordNeverExpires -eq $False
        } –Properties "DisplayName", "msDS-UserPasswordExpiryTimeComputed" |
        Select-Object -Property "DisplayName", @{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}})
    }

    Process {
        # Iterate through the list of all accounts
        $Accounts | ForEach-Object {

            # This checks if the account is set to Never Expire (Date would be set to 1600-12-31)
            If($_."ExpiryDate" -gt $NeverExpires) {
    
                # Calculate the time remaining between now and the expiry
                $TimeRemaining = (New-TimeSpan -End $_.ExpiryDate)

                If($ShowExpire) {
                    # If the password will expire in the next 30 days, save the information to an object
                    If($TimeRemaining.Days -gt 0 -and $TimeRemaining.Days -le 30) {
                        $ExpireSoon = New-Object PSObject -Property ( [Ordered] @{
                            UserName = $_.DisplayName
                            DaysRemaining = $TimeRemaining.Days
                            ExpiryDate = $_.ExpiryDate
                        })
                        $ExpireList += $ExpireSoon # Add the account to the expire list
                    }
                }
                #Else {
                #   If($TimeRemaining.Days -gt -31 -and $TimeRemaining.Days -le 0) {
                #        $RecentlyChanged = New-Object PSObject -Property ( [Ordered] @{
                #            UserName = $_.DisplayName
                #            DaysRemaining = $TimeRemaining.Days
                #            ExpiryDate = $_.ExpiryDate
                #        })
                #    }
                #}
            }
        }
        If($ShowExpire) {
            # Print out all the accounts expiring in the next 30 days
            $ExpireList | Sort-Object -Property DaysRemaining | Format-Table -AutoSize
        }
        Else {
            $LastChange | Sort-Object -Property WhenChanged | Format-Table -AutoSize
        }

    }
}

# =========================================================================================
# Script Begin!

Clear-Host
showHeader(" Authentication Required ")
$Credential = Authenticate

If($Credential) {
    Do {
        showHeader(" Main Menu ")
        Write-Host " 1. Unlock User Account"
        Write-Host " 2. Compare Two User Accounts"
        Write-Host " 3. Check Password Expiry"
        Write-Host " 0. Quit`n"
    
        $Prompt = grabValidInput
        Switch ($Prompt) {
            1 { 
                showHeader(" Unlock User ")
                Write-Host "Enter the name of the locked account firstname.lastname"
                $UserName = Read-Host ">>>"
                unlockUser($Credential, $UserName)
            }
            2 { 
                showHeader(" Compare Accounts ")
                Write-Host "Enter the first account to compare firstname.lastname"
                $FirstUser = Read-Host ">>>"
                Write-Host "Enter the second account to compare firstname.lastname"
                $SecondUser = Read-Host ">>>"
                compareAccounts($Credential, $FirstUser, $SecondUser)
            }
            3 { 
                showHeader(" Password Expiry Check ")
                passwordExpiryCheck($Credential, 30, $True)
            }
        }
    }
    Until($prompt -eq 0)
    Exit
} Else {
    Write-Host "Error: Authentication Failed" -ForegroundColor Red
    Exit
}
