
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
    for($index = 0; $index -lt $width; $index++) {
        # Print the title if at the half way point
        if($index -eq $startTitle ) {
            Write-Host -NoNewline $title
            $index = $index + $title.length
        }
        Write-Host -NoNewline "="
    }
    Write-Host "`n"
}

function ShowOptions {

}


function MainMenu {
    do {

        ShowHeader(" Main Menu ")

        $unlock = New-Object System.Management.Automation.Host.ChoiceDescription '&Unlock'
        $validateAccount = New-Object System.Management.Automation.Host.ChoiceDescription '&Validate Account'
        $lastChange = New-Object System.Management.Automation.Host.ChoiceDescription '&Last Change'
        $nextExpire = New-Object System.Management.Automation.Host.ChoiceDescription '&Next Expire'
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($unlock, $validateAccount, $lastChange, $nextExpire)
        $prompt = $Host.UI.PromptForChoice("", "Select the script to run", $options)

        switch ($prompt) {
            0 { 
                Clear-Host
                ShowHeader(" Unlock ")
                unlock 
            }
            1 { 
                Clear-Host
                ShowHeader(" Validate Account ")
                validateAccount
            }
            2 { 
                Clear-Host
                ShowHeader(" Next Expire ")
                checkExpire
            }
            3 {
                Clear-Host
                ShowHeader(" Last Changed ")
                lastChanged
            }
            4 {
                Clear-Host
                ShowHeader(" Help Menu ")
                helpMenu
            }
            Default {
                Write-Host "Invalid Entry" -ForegroundColor Red
                Start-Sleep -Seconds 2
                Clear-Host
            }
        }
    }
    until($prompt -eq "q")
}

function helpMenu {
    Write-Host "Add help menu"
}

# Unlock a specified users account
function unlock {

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

# Show all passwords expiring in the next 30 days
function checkExpire {
    param ( $DaysUntilExpired )

    Get-ADUser -filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} –Properties "DisplayName", "msDS-UserPasswordExpiryTimeComputed" |
    Select-Object -Property "Displayname",@{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}} #|
    #Where-Object ($_.ExpiryDate -lt )
}

# Show all passwords changed in the last 30 days
function lastChanged {

}

function validateAccount {

    $Usercomparison = @()

    $user1 = Get-ADUser Nathan.Mcbride -Properties *
    $user2 = Get-ADUser Frank.Zappa -Properties *

    $user1.GetEnumerator() | ForEach-Object {

        If ($User2.($_.Key) -eq $_.Value) { 
                 $Comparison = 'Equal'
        } else { $Comparison = 'Different' } 

        $UserObj = New-Object PSObject -Property ([ordered]@{
            Property = $_.Key
            User1 = $_.Value
            User2 = $User2.($_.Key)
            Comparison = $Comparison
        })

        $UserComparison += $UserObj
    }

    $Usercomparison | Format-Table
}

# Begin!
if(Authenticate) { 
    MainMenu
    Exit 
} 
else {
    Write-Host "You must be a Domain Administrator to run this script." -ForegroundColor Red
    Exit
}