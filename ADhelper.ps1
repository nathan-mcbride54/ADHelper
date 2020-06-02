# ==============================================
# Name: ADhelper.ps1
# 
# Description:
#   This script was designed 
#
#
#
# ==============================================

# 
Function Authenticate {
    $Credential = $host.ui.PromptForCredential("Authentication Required", "Please enter your Domain Admin credentials.", "", "NetBiosUserName") 

    # Get current domain using logged-on user's credentials
    $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName

    # Test the credentials by creating a new directory entry 
    $Domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$Credential.UserName,$Credential.GetNetworkCredential().password)

    if ($Domain.name -eq $null) {
        write-host "Authentication failed - please verify your username and password." -ForegroundColor Red
        Exit
    }
    else {
        write-host "Authentication Sucessful" -ForegroundColor Green
        Return $Credential
    }
}

# Prompts the user for an input and wont return unless it's valid
Function grabValidInput {
    [bool]$Valid = $false

    While($Valid -eq $false) {
        $Prompt = Read-Host ">>>"
        # Valid Inputs are specified here
        If($Prompt -eq 0 || 1 || 2 || 3 ) {
            $Valid = $true
        } 
        else {
            Write-Host "Invalid Input" -ForegroundColor Red
        }
    }
    Return $prompt
}

# Displays a header containing the page title for style
Function showHeader {
    param($Title)
    $Width = $Host.UI.RawUI.WindowSize.Width
    $StartTitle = [math]::Floor((($Width / 2) - ($Title.length / 2)))

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

# Unlock a specified users account
function unlockUser {
    param($Authorization, $UserName)

    # Search for a locked out account matching the name provided by the user.
    $ADaccount = Search-ADAccount -LockedOut -Credential $Authorization | Where-Object { $_.SamAccountName -match $UserName.ToString() }
    if( ($ADaccount) ) {
        Unlock-ADAccount -Identity $ADaccount -Credential $Authorization
        Write-Host $ADaccount.SamAccountName "unlocked sucessfuly" -ForegroundColor Green
    }
    # Account does not exist or is not locked.
    else {   
        Write-Host "$UserName not listed as a locked account..." -ForegroundColor Red
    }
}

function compareAccounts {
    param($Authorization, $FirstUser, $SecondUser)

    $Usercomparison = @()
    $ADUser1 = Get-ADUser $FirstUser -Properties * -Credential $Authorization
    $ADUser2 = Get-ADUser $SecondUser -Properties * -Credential $Authorization

    $ADUser1.GetEnumerator() | ForEach-Object {

        If ($ADUser2.($_.Key) -eq $_.Value) { 
            $Match = $true
        } else { 
            $Match = $false
        }

        $UserObj = New-Object PSObject -Property ([ordered]@{
            Property = $_.Key
            User1 = $_.Value
            User2 = $ADUser2.($_.Key)
            Match = $Match
        })
        $UserComparison += $UserObj
    }

    For($index = 0; $index -lt $Usercomparison.length; $index ++) {
        If($Usercomparison[$index].Match) {
            Write-Host $Usercomparison[$index].Property -ForegroundColor Green
        }
        else {
            Write-Host $Usercomparison[$index].Property -ForegroundColor Red
        }
    }
}

function passwordCheck {
    param ($Authorization, $DaysUntilExpired)

    $ExpireList = (Get-ADUser -filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} –Properties "DisplayName", "msDS-UserPasswordExpiryTimeComputed" |
    Select-Object -Property "Displayname",@{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}})

    # Make expire list a hash table
    # Loop through each object comparing dates
    # If the date matches print the object
    $ExpireList.GetEnumerator() | ForEach-Object {
       # If()
    }


    
}

# Begin Script!
showHeader(" Authentication Required ")
$Credential = Authenticate

If($Credential) {
    Do {
        showHeader(" Main Menu ")
        Write-Host " 1. Unlock User Account"
        Write-Host " 2. Compare Two User Accounts"
        Write-Host " 3. Check Password Changes"
        Write-Host " 0. Quit`n"
    
        $prompt = grabValidInput
        Switch ($prompt) {
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
                showHeader(" Password Check ")
                Write-Host "Show last changed or next to expire?"
                $select = Read-Host ">>>"
                passwordCheck($Credential, $DaysUntilExpired)
            }
        }
    }
    Until($prompt -eq 0)
    Exit
}
