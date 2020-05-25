

$CurrentUser = $(whoami.exe).toString().replace("cronos\", "")
[bool]$IsDomainAdmin = (Get-ADUser $CurrentUser -Properties memberof).memberof -contains (Get-ADGroup "Domain Admins")  

if($IsDomainAdmin) {
    Write-Host "Authenticated as: $CurrentUser"
    MainMenu($CurrentUser)
}
else {
    Write-Host "You must run this program as a Domain Administrator" -ForegroundColor Red
    Exit
}

function MainMenu {
    param ( $CurrentUser )
    [bool]$Quit = $false
    while ( -not $Quit ) {
        $input = Read-Host "[ $CurrentUser ] $ "

        switch ($input) {
            1 { }
            2 { }
            3 { }
            "Q" { Exit }
            Default {}
        }
    }
}

function unlock {
    param ( $UserName )
    # Search for a locked out account matching the name provided by the user.
    $ADaccount = Search-ADAccount -LockedOut | Where-Object { $_.SamAccountName -match $UserName }
    if( ($ADaccount) ) {
        Unlock-ADAccount -Identity $ADaccount
        Write-Host $ADaccount.SamAccountName "unlocked sucessfuly" -ForegroundColor Green
    }
    # Account does not exist or is not locked.
    else {   
        Write-Host "$UserName not listed as a locked account..." -ForegroundColor Red
    }
}

function checkExpire {
    param ( $DaysUntilExpired )

    Get-ADUser -filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} –Properties "DisplayName", "msDS-UserPasswordExpiryTimeComputed" |
    Select-Object -Property "Displayname",@{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}} #|
    #Where-Object ($_.ExpiryDate -lt )

}