# Name: ADhelper.ps1
# 
#
#
#


# This function returns true if the shell is being run by a Domain Admin and false if not.
function Authenticate {
    $CurrentUser = $(whoami.exe).toString().replace("cronos\", "")
    [bool]$IsDomainAdmin = (Get-ADUser $CurrentUser -Properties memberof).memberof -contains (Get-ADGroup "Domain Admins")  
    return $IsDomainAdmin
}

function ShowHeader {
    param( $title )
    $width = $Host.UI.RawUI.WindowSize.Width
    $startTitle = [math]::Floor((($width / 2) - ($title.length / 2)))

    Write-Host "`n"
    for($index = 0; $index -lt $width; $index++) {
        if($index -eq $startTitle ) {
            Write-Host $title -NoNewline -ForegroundColor Green
            $index = $index + $title.length
        }
        Write-Host -NoNewline "="
    }
    Write-Host "`n"
}

# Unlock a specified users account
function unlockUser {

    Write-Host "Enter the name of the locked account firstname.lastname"
    $UserName = Read-Host ">>>"

    # Search for a locked out account matching the name provided by the user.
    $ADaccount = Search-ADAccount -LockedOut | Where-Object { $_.SamAccountName -match $UserName.ToString() }
    if( ($ADaccount) ) {
        Unlock-ADAccount -Identity $ADaccount
        Write-Host $ADaccount.SamAccountName "unlocked sucessfuly" -ForegroundColor Green
    }
    # Account does not exist or is not locked.
    else {   
        Write-Host "$UserName not listed as a locked account..." -ForegroundColor Red
    }
}

function passwordUpdates {
    param ( $DaysUntilExpired )

    $ExpireList = (Get-ADUser -filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} –Properties "DisplayName", "msDS-UserPasswordExpiryTimeComputed" |
    Select-Object -Property "Displayname",@{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}})
    
}

function compareAccounts {

    param($FirstUser, $SecondUser)

    $Usercomparison = @()

    $ADUser1 = Get-ADUser $FirstUser -Properties *
    $ADUser2 = Get-ADUser $SecondUser -Properties *

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

# Begin!
#if(Authenticate) { 

    $unlockUser = New-Object System.Management.Automation.Host.ChoiceDescription '&Unlock User'
    $compareAccounts = New-Object System.Management.Automation.Host.ChoiceDescription '&Compare Accounts'
    $passwordUpdates = New-Object System.Management.Automation.Host.ChoiceDescription '&Password Updates'
    $validOptions = [System.Management.Automation.Host.ChoiceDescription[]]($unlockUser, $compareAccounts, $passwordUpdates)

    do {
        ShowHeader(" Main Menu ")
        $prompt = $Host.UI.PromptForChoice("", "", $validOptions, 0)

        switch ($prompt) {
            0 { 
                ShowHeader(" Unlock User ")
                unlockUser 
            }
            1 { 
                ShowHeader(" Compare Accounts ")
                compareAccounts
            }
            2 { 
                ShowHeader(" Password Updates ")
                passwordUpdates
            }
            Default {
                Write-Host "Invalid Entry" -ForegroundColor Red
            }
        }
    }
    until($prompt -eq "q") # Fix no quit bug

    Exit 
#} 
#else {
#    Write-Host "You must be a Domain Administrator to run this script." -ForegroundColor Red
#    Exit
#}