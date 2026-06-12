Set-StrictMode -Version Latest

function New-GlauthUserRecord {
    param(
        [string]$Name = '',
        [int]$UidNumber = 0,
        [int]$PrimaryGroup = 0
    )

    [pscustomobject]@{
        Name                 = $Name
        GivenName            = ''
        Surname              = ''
        Mail                 = ''
        UidNumber            = $UidNumber
        PrimaryGroup         = $PrimaryGroup
        OtherGroups          = @()
        LoginShell           = ''
        HomeDir              = ''
        PassSha256           = ''
        PassBcrypt           = ''
        Disabled             = $false
        OtpSecret            = ''
        YubiKey              = ''
        AdditionalProperties = [ordered]@{}
        ExtraContent         = @()
    }
}

function New-GlauthGroupRecord {
    param(
        [string]$Name = '',
        [int]$GidNumber = 0
    )

    [pscustomobject]@{
        Name                 = $Name
        GidNumber            = $GidNumber
        IncludeGroups        = @()
        IncludeGroupsDisplay = ''
        AdditionalProperties = [ordered]@{}
        ExtraContent         = @()
    }
}

function New-GlauthConfigRecord {
    [pscustomobject]@{
        PrefixText  = ''
        BetweenText = ''
        SuffixText  = ''
        Users       = (New-Object System.Collections.ArrayList)
        Groups      = (New-Object System.Collections.ArrayList)
    }
}

function Get-TopLevelSectionMatches {
    param([string]$Text)

    return [regex]::Matches($Text, '(?m)^(?<header>\[\[[^\r\n]+\]\]|\[[^\r\n]+\])\s*$')
}

function Remove-GlauthInlineComment {
    param([string]$Text)

    if ([string]::IsNullOrEmpty($Text)) {
        return $Text
    }

    $inQuotes = $false
    $previous = [char]0

    for ($index = 0; $index -lt $Text.Length; $index++) {
        $current = $Text[$index]
        if ($current -eq '"' -and $previous -ne '\') {
            $inQuotes = -not $inQuotes
        }

        if ($current -eq '#' -and -not $inQuotes) {
            return $Text.Substring(0, $index).TrimEnd()
        }

        $previous = $current
    }

    return $Text.TrimEnd()
}

function ConvertFrom-GlauthString {
    param([string]$Value)

    if ($Value.Length -ge 2 -and $Value.StartsWith('"') -and $Value.EndsWith('"')) {
        $inner = $Value.Substring(1, $Value.Length - 2)
        $inner = $inner.Replace('\"', '"')
        $inner = $inner.Replace('\\', '\')
        return $inner
    }

    return $Value
}

function Split-GlauthArrayItems {
    param([string]$Text)

    $items = New-Object System.Collections.ArrayList
    $builder = New-Object System.Text.StringBuilder
    $inQuotes = $false
    $previous = [char]0

    foreach ($character in $Text.ToCharArray()) {
        if ($character -eq '"' -and $previous -ne '\') {
            $inQuotes = -not $inQuotes
        }

        if ($character -eq ',' -and -not $inQuotes) {
            $token = $builder.ToString().Trim()
            if ($token) {
                [void]$items.Add($token)
            }

            [void]$builder.Clear()
            $previous = $character
            continue
        }

        [void]$builder.Append($character)
        $previous = $character
    }

    $lastToken = $builder.ToString().Trim()
    if ($lastToken) {
        [void]$items.Add($lastToken)
    }

    return ,$items
}

function ConvertFrom-GlauthValue {
    param([string]$RawValue)

    $value = (Remove-GlauthInlineComment -Text $RawValue).Trim()
    if (-not $value) {
        return ''
    }

    if ($value.StartsWith('[') -and $value.EndsWith(']')) {
        $inner = $value.Substring(1, $value.Length - 2).Trim()
        if (-not $inner) {
            return @()
        }

        $result = New-Object System.Collections.ArrayList
        foreach ($item in (Split-GlauthArrayItems -Text $inner)) {
            [void]$result.Add((ConvertFrom-GlauthValue -RawValue $item))
        }

        return ,$result.ToArray()
    }

    if ($value -match '^(true|false)$') {
        return [System.Convert]::ToBoolean($matches[1])
    }

    if ($value -match '^-?\d+$') {
        return [int]$value
    }

    return (ConvertFrom-GlauthString -Value $value)
}

function Escape-GlauthString {
    param([string]$Value)

    $escaped = $Value.Replace('\', '\\')
    $escaped = $escaped.Replace('"', '\"')
    return '"' + $escaped + '"'
}

function ConvertTo-GlauthValue {
    param($Value)

    if ($null -eq $Value) {
        return '""'
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = @()
        foreach ($item in $Value) {
            $items += (ConvertTo-GlauthValue -Value $item)
        }

        if ($items.Count -eq 0) {
            return '[]'
        }

        return '[ ' + ($items -join ', ') + ' ]'
    }

    if ($Value -is [bool]) {
        if ($Value) {
            return 'true'
        }

        return 'false'
    }

    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64]) {
        return [string]$Value
    }

    return (Escape-GlauthString -Value ([string]$Value))
}

function Get-GlauthBaseDnFromText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $match = [regex]::Match($Text, '(?im)^\s*baseDN\s*=\s*"(?<value>[^"]+)"\s*$')
    if (-not $match.Success) {
        return ''
    }

    return $match.Groups['value'].Value.Trim()
}

function Convert-GlauthBaseDnToMailDomain {
    param([string]$BaseDn)

    if ([string]::IsNullOrWhiteSpace($BaseDn)) {
        return ''
    }

    $domainParts = @()
    foreach ($segment in ($BaseDn -split '\s*,\s*')) {
        if ($segment -match '^(?i)dc=(?<value>.+)$') {
            $domainParts += $matches['value'].Trim()
        }
    }

    if ($domainParts.Count -eq 0) {
        return ''
    }

    return (($domainParts | Where-Object { $_ }) -join '.').ToLowerInvariant()
}

function Get-GlauthMailDomainFromConfig {
    param($Config)

    $configText = '{0}{1}{2}' -f $Config.PrefixText, $Config.BetweenText, $Config.SuffixText
    $baseDn = Get-GlauthBaseDnFromText -Text $configText
    return (Convert-GlauthBaseDnToMailDomain -BaseDn $baseDn)
}

function Get-GlauthDerivedMailAddress {
    param(
        $Config,
        [string]$UserName
    )

    if ([string]::IsNullOrWhiteSpace($UserName)) {
        return ''
    }

    $domain = Get-GlauthMailDomainFromConfig -Config $Config
    if ([string]::IsNullOrWhiteSpace($domain)) {
        return ''
    }

    return ('{0}@{1}' -f $UserName.Trim(), $domain)
}

function Sync-GlauthUserMailAddresses {
    param($Config)

    $domain = Get-GlauthMailDomainFromConfig -Config $Config
    if ([string]::IsNullOrWhiteSpace($domain)) {
        return
    }

    foreach ($user in $Config.Users) {
        $userName = [string](Get-ObjectPropertyValue -Object $user -PropertyName 'Name' '')
        if (-not [string]::IsNullOrWhiteSpace($userName)) {
            $user.Mail = ('{0}@{1}' -f $userName.Trim(), $domain)
        }
    }
}

function Get-ObjectPropertyValue {
    param(
        $Object,
        [string]$PropertyName,
        $DefaultValue = $null
    )

    if ($null -eq $Object) {
        return $DefaultValue
    }

    $property = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return $DefaultValue
    }

    return $property.Value
}

function ConvertFrom-GlauthEntityBlock {
    param(
        [string]$BlockText,
        [ValidateSet('users', 'groups')]
        [string]$EntityType
    )

    $knownKeys = @{
        users  = @('name', 'givenname', 'sn', 'mail', 'uidnumber', 'primarygroup', 'othergroups', 'loginshell', 'homedir', 'passsha256', 'passbcrypt', 'disabled', 'otpsecret', 'yubikey')
        groups = @('name', 'gidnumber', 'includegroups')
    }

    $lines = $BlockText -split "\r?\n"
    $parsed = @{}
    $additional = [ordered]@{}
    $extra = New-Object System.Collections.ArrayList
    $capturingMultiline = $false

    for ($index = 1; $index -lt $lines.Count; $index++) {
        $line = $lines[$index]
        $trimmed = $line.Trim()

        if ($capturingMultiline) {
            [void]$extra.Add($line)
            if ((Remove-GlauthInlineComment -Text $trimmed).Trim().EndsWith(']')) {
                $capturingMultiline = $false
            }

            continue
        }

        if ($line -match '^\s{2}([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$') {
            $key = $matches[1]
            $normalizedKey = $key.ToLowerInvariant()
            $rawValue = $matches[2]
            $commentFreeValue = (Remove-GlauthInlineComment -Text $rawValue).Trim()

            if ($commentFreeValue.StartsWith('[') -and -not $commentFreeValue.EndsWith(']')) {
                [void]$extra.Add($line)
                $capturingMultiline = $true
                continue
            }

            $parsedValue = ConvertFrom-GlauthValue -RawValue $rawValue
            if ($knownKeys[$EntityType] -contains $normalizedKey) {
                $parsed[$normalizedKey] = $parsedValue
            }
            else {
                $additional[$key] = $parsedValue
            }

            continue
        }

        [void]$extra.Add($line)
    }

    if ($EntityType -eq 'users') {
        $record = New-GlauthUserRecord
        $record.Name = [string]$parsed['name']
        $record.GivenName = [string]$parsed['givenname']
        $record.Surname = [string]$parsed['sn']
        $record.Mail = [string]$parsed['mail']
        if ($parsed.ContainsKey('uidnumber')) { $record.UidNumber = [int]$parsed['uidnumber'] }
        if ($parsed.ContainsKey('primarygroup')) { $record.PrimaryGroup = [int]$parsed['primarygroup'] }
        if ($parsed.ContainsKey('othergroups')) { $record.OtherGroups = @($parsed['othergroups']) }
        $record.LoginShell = [string]$parsed['loginshell']
        $record.HomeDir = [string]$parsed['homedir']
        $record.PassSha256 = [string]$parsed['passsha256']
        $record.PassBcrypt = [string]$parsed['passbcrypt']
        if ($parsed.ContainsKey('disabled')) { $record.Disabled = [bool]$parsed['disabled'] }
        $record.OtpSecret = [string]$parsed['otpsecret']
        $record.YubiKey = [string]$parsed['yubikey']
        $record.AdditionalProperties = $additional
        $record.ExtraContent = @($extra)
        return $record
    }

    $groupRecord = New-GlauthGroupRecord
    $groupRecord.Name = [string]$parsed['name']
    if ($parsed.ContainsKey('gidnumber')) { $groupRecord.GidNumber = [int]$parsed['gidnumber'] }
    if ($parsed.ContainsKey('includegroups')) { $groupRecord.IncludeGroups = @($parsed['includegroups']) }
    $groupRecord.IncludeGroupsDisplay = (($groupRecord.IncludeGroups | ForEach-Object { [string]$_ }) -join ', ')
    $groupRecord.AdditionalProperties = $additional
    $groupRecord.ExtraContent = @($extra)
    return $groupRecord
}

function ConvertFrom-GlauthConfigText {
    param([string]$Text)

    $config = New-GlauthConfigRecord
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $config
    }

    $sectionMatches = Get-TopLevelSectionMatches -Text $Text
    if ($sectionMatches.Count -eq 0) {
        $config.PrefixText = $Text
        return $config
    }

    $blocks = New-Object System.Collections.ArrayList
    for ($index = 0; $index -lt $sectionMatches.Count; $index++) {
        $match = $sectionMatches[$index]
        $header = $match.Groups['header'].Value
        $nextIndex = $Text.Length
        if ($index -lt ($sectionMatches.Count - 1)) {
            $nextIndex = $sectionMatches[$index + 1].Index
        }

        if ($header -ne '[[users]]' -and $header -ne '[[groups]]') {
            continue
        }

        $type = if ($header -eq '[[users]]') { 'users' } else { 'groups' }
        $blockText = $Text.Substring($match.Index, $nextIndex - $match.Index).TrimEnd()
        [void]$blocks.Add([pscustomobject]@{
                Type      = $type
                StartIndex = $match.Index
                EndIndex   = $nextIndex
                Text       = $blockText
            })
    }

    if ($blocks.Count -eq 0) {
        $config.PrefixText = $Text
        return $config
    }

    $userBlocks = @($blocks | Where-Object { $_.Type -eq 'users' } | Sort-Object StartIndex)
    $groupBlocks = @($blocks | Where-Object { $_.Type -eq 'groups' } | Sort-Object StartIndex)

    foreach ($block in $userBlocks) {
        [void]$config.Users.Add((ConvertFrom-GlauthEntityBlock -BlockText $block.Text -EntityType 'users'))
    }

    foreach ($block in $groupBlocks) {
        [void]$config.Groups.Add((ConvertFrom-GlauthEntityBlock -BlockText $block.Text -EntityType 'groups'))
    }

    if ($userBlocks.Count -gt 0) {
        $config.PrefixText = $Text.Substring(0, $userBlocks[0].StartIndex)

        if ($groupBlocks.Count -gt 0) {
            $lastUser = $userBlocks[$userBlocks.Count - 1]
            $firstGroup = $groupBlocks[0]
            $lastGroup = $groupBlocks[$groupBlocks.Count - 1]
            $config.BetweenText = $Text.Substring($lastUser.EndIndex, $firstGroup.StartIndex - $lastUser.EndIndex)
            $config.SuffixText = $Text.Substring($lastGroup.EndIndex)
        }
        else {
            $lastUserOnly = $userBlocks[$userBlocks.Count - 1]
            $config.SuffixText = $Text.Substring($lastUserOnly.EndIndex)
        }
    }
    elseif ($groupBlocks.Count -gt 0) {
        $config.PrefixText = $Text.Substring(0, $groupBlocks[0].StartIndex)
        $lastGroupOnly = $groupBlocks[$groupBlocks.Count - 1]
        $config.SuffixText = $Text.Substring($lastGroupOnly.EndIndex)
    }

    return $config
}

function Add-GlauthPropertyLine {
    param(
        [System.Collections.ArrayList]$Lines,
        [string]$Key,
        $Value
    )

    if ($null -eq $Value) {
        return
    }

    if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) {
        return
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string] -and (@($Value).Count -eq 0)) {
        return
    }

    [void]$Lines.Add(('  {0} = {1}' -f $Key, (ConvertTo-GlauthValue -Value $Value)))
}

function ConvertTo-GlauthUserBlock {
    param($User)

    $lines = New-Object System.Collections.ArrayList
    $additionalProperties = Get-ObjectPropertyValue -Object $User -PropertyName 'AdditionalProperties' ([ordered]@{})
    $extraContent = Get-ObjectPropertyValue -Object $User -PropertyName 'ExtraContent' @()
    [void]$lines.Add('[[users]]')
    Add-GlauthPropertyLine -Lines $lines -Key 'name' -Value (Get-ObjectPropertyValue -Object $User -PropertyName 'Name' '')
    Add-GlauthPropertyLine -Lines $lines -Key 'givenname' -Value (Get-ObjectPropertyValue -Object $User -PropertyName 'GivenName' '')
    Add-GlauthPropertyLine -Lines $lines -Key 'sn' -Value (Get-ObjectPropertyValue -Object $User -PropertyName 'Surname' '')
    Add-GlauthPropertyLine -Lines $lines -Key 'mail' -Value (Get-ObjectPropertyValue -Object $User -PropertyName 'Mail' '')
    Add-GlauthPropertyLine -Lines $lines -Key 'uidnumber' -Value (Get-ObjectPropertyValue -Object $User -PropertyName 'UidNumber' 0)
    Add-GlauthPropertyLine -Lines $lines -Key 'primarygroup' -Value (Get-ObjectPropertyValue -Object $User -PropertyName 'PrimaryGroup' 0)
    Add-GlauthPropertyLine -Lines $lines -Key 'othergroups' -Value @(Get-ObjectPropertyValue -Object $User -PropertyName 'OtherGroups' @())
    Add-GlauthPropertyLine -Lines $lines -Key 'loginShell' -Value (Get-ObjectPropertyValue -Object $User -PropertyName 'LoginShell' '')
    Add-GlauthPropertyLine -Lines $lines -Key 'homeDir' -Value (Get-ObjectPropertyValue -Object $User -PropertyName 'HomeDir' '')
    Add-GlauthPropertyLine -Lines $lines -Key 'passsha256' -Value (Get-ObjectPropertyValue -Object $User -PropertyName 'PassSha256' '')
    Add-GlauthPropertyLine -Lines $lines -Key 'passbcrypt' -Value (Get-ObjectPropertyValue -Object $User -PropertyName 'PassBcrypt' '')
    if ([bool](Get-ObjectPropertyValue -Object $User -PropertyName 'Disabled' $false)) {
        Add-GlauthPropertyLine -Lines $lines -Key 'disabled' -Value $true
    }
    Add-GlauthPropertyLine -Lines $lines -Key 'otpsecret' -Value (Get-ObjectPropertyValue -Object $User -PropertyName 'OtpSecret' '')
    Add-GlauthPropertyLine -Lines $lines -Key 'yubikey' -Value (Get-ObjectPropertyValue -Object $User -PropertyName 'YubiKey' '')

    foreach ($key in $additionalProperties.Keys) {
        Add-GlauthPropertyLine -Lines $lines -Key $key -Value $additionalProperties[$key]
    }

    foreach ($line in $extraContent) {
        [void]$lines.Add($line)
    }

    return ($lines -join "`r`n").TrimEnd()
}

function ConvertTo-GlauthGroupBlock {
    param($Group)

    $lines = New-Object System.Collections.ArrayList
    $additionalProperties = Get-ObjectPropertyValue -Object $Group -PropertyName 'AdditionalProperties' ([ordered]@{})
    $extraContent = Get-ObjectPropertyValue -Object $Group -PropertyName 'ExtraContent' @()
    [void]$lines.Add('[[groups]]')
    Add-GlauthPropertyLine -Lines $lines -Key 'name' -Value (Get-ObjectPropertyValue -Object $Group -PropertyName 'Name' '')
    Add-GlauthPropertyLine -Lines $lines -Key 'gidnumber' -Value (Get-ObjectPropertyValue -Object $Group -PropertyName 'GidNumber' 0)
    Add-GlauthPropertyLine -Lines $lines -Key 'includegroups' -Value @(Get-ObjectPropertyValue -Object $Group -PropertyName 'IncludeGroups' @())

    foreach ($key in $additionalProperties.Keys) {
        Add-GlauthPropertyLine -Lines $lines -Key $key -Value $additionalProperties[$key]
    }

    foreach ($line in $extraContent) {
        [void]$lines.Add($line)
    }

    return ($lines -join "`r`n").TrimEnd()
}

function ConvertTo-GlauthConfigText {
    param($Config)

    $userText = ''
    if ($Config.Users.Count -gt 0) {
        $userText = (($Config.Users | ForEach-Object { ConvertTo-GlauthUserBlock -User $_ }) -join "`r`n`r`n").Trim()
    }

    $groupText = ''
    if ($Config.Groups.Count -gt 0) {
        $groupText = (($Config.Groups | ForEach-Object { ConvertTo-GlauthGroupBlock -Group $_ }) -join "`r`n`r`n").Trim()
    }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append($Config.PrefixText)

    if ($userText) {
        if ($builder.Length -gt 0 -and -not $builder.ToString().EndsWith("`n")) {
            [void]$builder.Append("`r`n")
        }

        [void]$builder.Append($userText)
        [void]$builder.Append("`r`n")
    }

    if ($groupText) {
        $betweenText = $Config.BetweenText
        if (-not $betweenText -and $userText) {
            $betweenText = "`r`n#################`r`n# The groups section contains a hardcoded list of valid users.`r`n"
        }

        [void]$builder.Append($betweenText)
        if ($builder.Length -gt 0 -and -not $builder.ToString().EndsWith("`n")) {
            [void]$builder.Append("`r`n")
        }

        [void]$builder.Append($groupText)
        [void]$builder.Append("`r`n")
    }

    if ($Config.SuffixText -and -not $Config.SuffixText.StartsWith("`r") -and -not $Config.SuffixText.StartsWith("`n") -and $builder.Length -gt 0) {
        [void]$builder.Append("`r`n")
    }

    [void]$builder.Append($Config.SuffixText)
    return $builder.ToString().TrimEnd() + "`r`n"
}

function Get-KubectlCommonArguments {
    param(
        [string]$KubeConfigPath,
        [string]$Context
    )

    $arguments = @()
    if ($KubeConfigPath) {
        $arguments += @('--kubeconfig', $KubeConfigPath)
    }

    if ($Context) {
        $arguments += @('--context', $Context)
    }

    return ,$arguments
}

function Get-KubeConfigContexts {
    param([string]$KubeConfigPath)

    $arguments = @((Get-KubectlCommonArguments -KubeConfigPath $KubeConfigPath -Context ''))
    $arguments += @('config', 'get-contexts', '-o', 'name')
    $output = & kubectl @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ('kubectl config get-contexts failed: {0}' -f ($output -join [Environment]::NewLine))
    }

    return @($output | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Get-KubeConfigCurrentContext {
    param([string]$KubeConfigPath)

    $arguments = @((Get-KubectlCommonArguments -KubeConfigPath $KubeConfigPath -Context ''))
    $arguments += @('config', 'current-context')
    $output = & kubectl @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        return ''
    }

    return (($output | Select-Object -First 1) -as [string]).Trim()
}

function Get-BcryptAssemblyPath {
    $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
    return (Join-Path -Path $moduleRoot -ChildPath 'lib\netstandard2.0\BCrypt.Net-Next.dll')
}

function Initialize-BcryptLibrary {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw 'BCrypt generation requires PowerShell 7 or newer.'
    }

    $assemblyLoaded = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'BCrypt.Net-Next' } | Select-Object -First 1
    if ($assemblyLoaded) {
        return
    }

    $assemblyPath = Get-BcryptAssemblyPath
    if (-not (Test-Path -LiteralPath $assemblyPath)) {
        throw ('BCrypt library not found at "{0}".' -f $assemblyPath)
    }

    [void][System.Reflection.Assembly]::LoadFrom($assemblyPath)
}

function ConvertTo-HexString {
    param([byte[]]$Bytes)

    return ([System.BitConverter]::ToString($Bytes).Replace('-', '').ToLowerInvariant())
}

function ConvertTo-GlauthBcryptHash {
    param([string]$Password)

    if ([string]::IsNullOrEmpty($Password)) {
        throw 'Password is required.'
    }

    Initialize-BcryptLibrary
    $bcryptString = [BCrypt.Net.BCrypt]::HashPassword($Password, 10)
    $bcryptBytes = [System.Text.Encoding]::ASCII.GetBytes($bcryptString)
    return (ConvertTo-HexString -Bytes $bcryptBytes)
}

function Get-GlauthConfigMapObject {
    param(
        [string]$KubeConfigPath,
        [string]$Context,
        [string]$Namespace,
        [string]$ConfigMapName
    )

    $arguments = @((Get-KubectlCommonArguments -KubeConfigPath $KubeConfigPath -Context $Context))
    $arguments += @('get', 'configmap', $ConfigMapName, '-n', $Namespace, '-o', 'json')
    $output = & kubectl @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ('kubectl get configmap failed: {0}' -f ($output -join [Environment]::NewLine))
    }

    return ($output -join [Environment]::NewLine | ConvertFrom-Json)
}

function Get-GlauthConfigFromCluster {
    param(
        [string]$KubeConfigPath,
        [string]$Context,
        [string]$Namespace,
        [string]$ConfigMapName,
        [string]$DataKey
    )

    $configMapObject = Get-GlauthConfigMapObject -KubeConfigPath $KubeConfigPath -Context $Context -Namespace $Namespace -ConfigMapName $ConfigMapName
    $dataEntry = $configMapObject.data.PSObject.Properties[$DataKey]
    if ($null -eq $dataEntry) {
        throw ('ConfigMap "{0}" does not contain data key "{1}".' -f $ConfigMapName, $DataKey)
    }

    return [pscustomobject]@{
        ConfigMapObject = $configMapObject
        ConfigText      = [string]$dataEntry.Value
    }
}

function Save-GlauthConfigToCluster {
    param(
        [string]$KubeConfigPath,
        [string]$Context,
        [string]$Namespace,
        [string]$ConfigMapName,
        [string]$DataKey,
        [string]$ConfigText,
        $ConfigMapObject
    )

    $configMapToUpdate = $ConfigMapObject
    if ($null -eq $configMapToUpdate) {
        $configMapToUpdate = Get-GlauthConfigMapObject -KubeConfigPath $KubeConfigPath -Context $Context -Namespace $Namespace -ConfigMapName $ConfigMapName
    }

    if ($null -eq $configMapToUpdate.data) {
        $configMapToUpdate | Add-Member -NotePropertyName data -NotePropertyValue ([pscustomobject]@{}) -Force
    }

    $existingProperty = $configMapToUpdate.data.PSObject.Properties[$DataKey]
    if ($null -eq $existingProperty) {
        $configMapToUpdate.data | Add-Member -NotePropertyName $DataKey -NotePropertyValue $ConfigText -Force
    }
    else {
        $existingProperty.Value = $ConfigText
    }

    $json = $configMapToUpdate | ConvertTo-Json -Depth 100
    $tempFile = [System.IO.Path]::GetTempFileName()

    try {
        [System.IO.File]::WriteAllText($tempFile, $json, [System.Text.Encoding]::UTF8)
        $arguments = @((Get-KubectlCommonArguments -KubeConfigPath $KubeConfigPath -Context $Context))
        $arguments += @('replace', '-f', $tempFile)
        $output = & kubectl @arguments 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ('kubectl replace failed: {0}' -f ($output -join [Environment]::NewLine))
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempFile) {
            Remove-Item -LiteralPath $tempFile -Force
        }
    }

    return (Get-GlauthConfigMapObject -KubeConfigPath $KubeConfigPath -Context $Context -Namespace $Namespace -ConfigMapName $ConfigMapName)
}

function ConvertFrom-IdListString {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }

    $items = New-Object System.Collections.ArrayList
    foreach ($token in ($Text -split '[,\s]+' | Where-Object { $_ })) {
        if ($token -notmatch '^\d+$') {
            throw ('"{0}" is not a valid numeric identifier.' -f $token)
        }

        [void]$items.Add([int]$token)
    }

    return ,$items.ToArray()
}

function ConvertTo-IdListString {
    param($Values)

    if ($null -eq $Values) {
        return ''
    }

    return ((@($Values) | ForEach-Object { [string]$_ }) -join ', ')
}

function Get-NextAvailableId {
    param(
        [System.Collections.IEnumerable]$Items,
        [string]$PropertyName,
        [int]$StartAt
    )

    $existingValues = @($Items | ForEach-Object { [int](Get-ObjectPropertyValue -Object $_ -PropertyName $PropertyName 0) })
    if ($existingValues.Count -eq 0) {
        return $StartAt
    }

    return (($existingValues | Measure-Object -Maximum).Maximum + 1)
}

function Format-PrimaryGroupChoice {
    param($Group)

    return ('{0} ({1})' -f [int](Get-ObjectPropertyValue -Object $Group -PropertyName 'GidNumber' 0), [string](Get-ObjectPropertyValue -Object $Group -PropertyName 'Name' ''))
}

function New-OtherGroupChoice {
    param(
        [int]$GidNumber,
        [string]$Name,
        [bool]$IsSelected = $false
    )

    [pscustomobject]@{
        GidNumber   = $GidNumber
        Name        = $Name
        Display     = ('{0} ({1})' -f $GidNumber, $Name)
        IsSelected  = $IsSelected
    }
}

function Resolve-PrimaryGroupId {
    param(
        $State,
        $Controls
    )

    $text = $Controls.UserPrimaryGroupComboBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw 'Primary Group is required.'
    }

    if ($text -match '^(?<gid>\d+)\s+\(.+\)$') {
        return [int]$matches['gid']
    }

    if ($text -match '^\d+$') {
        return [int]$text
    }

    $matchingGroup = @($State.Config.Groups | Where-Object { (Get-ObjectPropertyValue -Object $_ -PropertyName 'Name' '') -eq $text })
    if ($matchingGroup.Count -eq 1) {
        return [int](Get-ObjectPropertyValue -Object $matchingGroup[0] -PropertyName 'GidNumber' 0)
    }

    throw 'Primary Group must be a numeric gid or an existing role name.'
}

function TryResolve-PrimaryGroupId {
    param(
        $State,
        $Controls
    )

    try {
        return (Resolve-PrimaryGroupId -State $State -Controls $Controls)
    }
    catch {
        return $null
    }
}

function Show-GlauthUserManagerWindow {
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase

    $xamlPath = Join-Path -Path $PSScriptRoot -ChildPath 'GlauthUserManager.xaml'
    $xamlContent = Get-Content -LiteralPath $xamlPath -Raw
    $stringReader = New-Object System.IO.StringReader($xamlContent)
    $xmlReader = [System.Xml.XmlReader]::Create($stringReader)
    $window = [Windows.Markup.XamlReader]::Load($xmlReader)

    $controls = @{}
    foreach ($name in @(
            'KubeConfigPathTextBox', 'BrowseKubeConfigButton', 'RefreshContextsButton', 'ContextComboBox',
            'NamespaceTextBox', 'ConfigMapTextBox', 'DataKeyTextBox',
            'LoadClusterButton', 'SaveClusterButton', 'LoadFileButton', 'SaveFileButton', 'RefreshPreviewButton',
            'UsersGrid', 'NewUserButton', 'DeleteUserButton', 'SaveUserButton',
            'UserEditorGrid', 'UserNameTextBox', 'UserGivenNameTextBox', 'UserSurnameTextBox', 'UserMailTextBox', 'UserUidTextBox',
            'UserPrimaryGroupComboBox', 'UserOtherGroupsItemsControl', 'UserLoginShellTextBox', 'UserHomeDirTextBox',
            'UserPasswordBox', 'GeneratePasswordHashButton',
            'UserPassSha256TextBox', 'UserPassBcryptTextBox', 'UserOtpSecretTextBox', 'UserYubiKeyTextBox',
            'UserDisabledCheckBox',
            'GroupsGrid', 'NewGroupButton', 'DeleteGroupButton', 'SaveGroupButton',
            'GroupNameTextBox', 'GroupGidTextBox', 'GroupIncludeGroupsTextBox',
            'RawConfigTextBox', 'StatusTextBlock'
        )) {
        $controls[$name] = $window.FindName($name)
    }

    $state = [pscustomobject]@{
        Config            = (New-GlauthConfigRecord)
        CurrentUser       = $null
        CurrentGroup      = $null
        OtherGroupChoices = (New-Object System.Collections.ArrayList)
        SourcePath        = ''
        ConfigMapObject   = $null
    }

    function Set-Status {
        param([string]$Message)
        $controls.StatusTextBlock.Text = $Message
    }

    function Show-OperationMessage {
        param(
            [string]$Title,
            [string]$Message
        )

        [System.Windows.MessageBox]::Show($window, $Message, $Title, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
    }

    function Show-ErrorMessage {
        param(
            [string]$Title,
            [string]$Message
        )

        [System.Windows.MessageBox]::Show($window, $Message, $Title, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error) | Out-Null
    }

    function Refresh-ContextChoices {
        $contexts = @()
        try {
            $contexts = Get-KubeConfigContexts -KubeConfigPath $controls.KubeConfigPathTextBox.Text.Trim()
        }
        catch {
            $controls.ContextComboBox.ItemsSource = $null
            Set-Status $_.Exception.Message
            return
        }

        $previousText = $controls.ContextComboBox.Text
        $controls.ContextComboBox.ItemsSource = $null
        $controls.ContextComboBox.ItemsSource = $contexts

        $currentContext = Get-KubeConfigCurrentContext -KubeConfigPath $controls.KubeConfigPathTextBox.Text.Trim()
        if ($currentContext -and $contexts -contains $currentContext) {
            $controls.ContextComboBox.SelectedItem = $currentContext
            $controls.ContextComboBox.Text = $currentContext
        }
        elseif ($previousText -and $contexts -contains $previousText) {
            $controls.ContextComboBox.SelectedItem = $previousText
            $controls.ContextComboBox.Text = $previousText
        }
        elseif ($previousText) {
            $controls.ContextComboBox.Text = $previousText
        }

        Set-Status ('Loaded {0} Kubernetes context(s).' -f $contexts.Count)
    }

    function Refresh-RawConfigPreview {
        Sync-GlauthUserMailAddresses -Config $state.Config
        $controls.RawConfigTextBox.Text = ConvertTo-GlauthConfigText -Config $state.Config
    }

    function Refresh-UserMailPreview {
        $controls.UserMailTextBox.Text = Get-GlauthDerivedMailAddress -Config $state.Config -UserName $controls.UserNameTextBox.Text
    }

    function Refresh-OtherGroupChoices {
        $selectedGroupIds = @()
        foreach ($choice in $state.OtherGroupChoices) {
            if ($choice.IsSelected) {
                $selectedGroupIds += [int]$choice.GidNumber
            }
        }

        $primaryGroupId = TryResolve-PrimaryGroupId -State $state -Controls $controls
        $updatedChoices = New-Object System.Collections.ArrayList
        foreach ($group in $state.Config.Groups) {
            $groupId = [int](Get-ObjectPropertyValue -Object $group -PropertyName 'GidNumber' 0)
            $groupName = [string](Get-ObjectPropertyValue -Object $group -PropertyName 'Name' '')
            if ($null -ne $primaryGroupId -and $groupId -eq [int]$primaryGroupId) {
                continue
            }

            $isSelected = $selectedGroupIds -contains $groupId
            [void]$updatedChoices.Add((New-OtherGroupChoice -GidNumber $groupId -Name $groupName -IsSelected $isSelected))
        }

        $state.OtherGroupChoices = $updatedChoices
        $controls.UserOtherGroupsItemsControl.ItemsSource = $null
        $controls.UserOtherGroupsItemsControl.ItemsSource = $state.OtherGroupChoices
    }

    function Refresh-GroupViews {
        foreach ($group in $state.Config.Groups) {
            $group.IncludeGroupsDisplay = ConvertTo-IdListString -Values $group.IncludeGroups
        }

        $controls.GroupsGrid.ItemsSource = $null
        $controls.GroupsGrid.ItemsSource = $state.Config.Groups

        $controls.UserPrimaryGroupComboBox.ItemsSource = $null
        $controls.UserPrimaryGroupComboBox.ItemsSource = @($state.Config.Groups | ForEach-Object { Format-PrimaryGroupChoice -Group $_ })
        Refresh-OtherGroupChoices
    }

    function Refresh-UserViews {
        $controls.UsersGrid.ItemsSource = $null
        $controls.UsersGrid.ItemsSource = $state.Config.Users
    }

    function Set-UserEditorEnabled {
        param([bool]$IsEnabled)

        $controls.UserEditorGrid.IsEnabled = $IsEnabled
    }

    function Clear-UserEditor {
        $state.CurrentUser = $null
        Set-UserEditorEnabled -IsEnabled $false
        $controls.UserNameTextBox.Text = ''
        $controls.UserGivenNameTextBox.Text = ''
        $controls.UserSurnameTextBox.Text = ''
        Refresh-UserMailPreview
        $controls.UserUidTextBox.Text = ''
        $controls.UserPrimaryGroupComboBox.SelectedIndex = -1
        $controls.UserPrimaryGroupComboBox.Text = ''
        Refresh-OtherGroupChoices
        $controls.UserLoginShellTextBox.Text = ''
        $controls.UserHomeDirTextBox.Text = ''
        $controls.UserPassSha256TextBox.Text = ''
        $controls.UserPassBcryptTextBox.Text = ''
        $controls.UserPasswordBox.Password = ''
        $controls.UserOtpSecretTextBox.Text = ''
        $controls.UserYubiKeyTextBox.Text = ''
        $controls.UserDisabledCheckBox.IsChecked = $false
    }

    function Clear-GroupEditor {
        $state.CurrentGroup = $null
        $controls.GroupNameTextBox.Text = ''
        $controls.GroupGidTextBox.Text = ''
        $controls.GroupIncludeGroupsTextBox.Text = ''
    }

    function Select-User {
        param($User)

        if ($null -eq $User) {
            Clear-UserEditor
            return
        }

        $state.CurrentUser = $User
        Set-UserEditorEnabled -IsEnabled $true
        $controls.UserNameTextBox.Text = [string](Get-ObjectPropertyValue -Object $User -PropertyName 'Name' '')
        $controls.UserGivenNameTextBox.Text = [string](Get-ObjectPropertyValue -Object $User -PropertyName 'GivenName' '')
        $controls.UserSurnameTextBox.Text = [string](Get-ObjectPropertyValue -Object $User -PropertyName 'Surname' '')
        Refresh-UserMailPreview
        $uidNumber = Get-ObjectPropertyValue -Object $User -PropertyName 'UidNumber' 0
        $primaryGroup = Get-ObjectPropertyValue -Object $User -PropertyName 'PrimaryGroup' 0
        $controls.UserUidTextBox.Text = if ($uidNumber) { [string]$uidNumber } else { '' }
        if ($primaryGroup) {
            $matchingGroup = @($state.Config.Groups | Where-Object { [int](Get-ObjectPropertyValue -Object $_ -PropertyName 'GidNumber' 0) -eq [int]$primaryGroup } | Select-Object -First 1)
            if ($matchingGroup.Count -gt 0) {
                $controls.UserPrimaryGroupComboBox.Text = Format-PrimaryGroupChoice -Group $matchingGroup[0]
            }
            else {
                $controls.UserPrimaryGroupComboBox.Text = [string]$primaryGroup
            }
        }
        else {
            $controls.UserPrimaryGroupComboBox.Text = ''
        }
        Refresh-OtherGroupChoices
        $selectedOtherGroupIds = @(Get-ObjectPropertyValue -Object $User -PropertyName 'OtherGroups' @() | ForEach-Object { [int]$_ })
        foreach ($choice in $state.OtherGroupChoices) {
            $choice.IsSelected = $selectedOtherGroupIds -contains [int]$choice.GidNumber
        }
        $controls.UserOtherGroupsItemsControl.Items.Refresh()
        $controls.UserLoginShellTextBox.Text = [string](Get-ObjectPropertyValue -Object $User -PropertyName 'LoginShell' '')
        $controls.UserHomeDirTextBox.Text = [string](Get-ObjectPropertyValue -Object $User -PropertyName 'HomeDir' '')
        $controls.UserPassSha256TextBox.Text = [string](Get-ObjectPropertyValue -Object $User -PropertyName 'PassSha256' '')
        $controls.UserPassBcryptTextBox.Text = [string](Get-ObjectPropertyValue -Object $User -PropertyName 'PassBcrypt' '')
        $controls.UserPasswordBox.Password = ''
        $controls.UserOtpSecretTextBox.Text = [string](Get-ObjectPropertyValue -Object $User -PropertyName 'OtpSecret' '')
        $controls.UserYubiKeyTextBox.Text = [string](Get-ObjectPropertyValue -Object $User -PropertyName 'YubiKey' '')
        $controls.UserDisabledCheckBox.IsChecked = [bool](Get-ObjectPropertyValue -Object $User -PropertyName 'Disabled' $false)
    }

    function Focus-UserNameField {
        $window.Dispatcher.BeginInvoke([action]{
                [void]$controls.UserNameTextBox.Focus()
                $controls.UserNameTextBox.SelectAll()
            }, [System.Windows.Threading.DispatcherPriority]::Input) | Out-Null
    }

    function Select-Group {
        param($Group)

        if ($null -eq $Group) {
            Clear-GroupEditor
            return
        }

        $state.CurrentGroup = $Group
        $controls.GroupNameTextBox.Text = [string](Get-ObjectPropertyValue -Object $Group -PropertyName 'Name' '')
        $groupId = Get-ObjectPropertyValue -Object $Group -PropertyName 'GidNumber' 0
        $controls.GroupGidTextBox.Text = if ($groupId) { [string]$groupId } else { '' }
        $controls.GroupIncludeGroupsTextBox.Text = ConvertTo-IdListString -Values (Get-ObjectPropertyValue -Object $Group -PropertyName 'IncludeGroups' @())
    }

    function Load-ConfigText {
        param(
            [string]$ConfigText,
            [string]$SourcePath = '',
            $ConfigMapObject = $null
        )

        $state.Config = ConvertFrom-GlauthConfigText -Text $ConfigText
        Sync-GlauthUserMailAddresses -Config $state.Config
        $state.SourcePath = $SourcePath
        $state.ConfigMapObject = $ConfigMapObject
        Refresh-GroupViews
        Refresh-UserViews
        Refresh-RawConfigPreview
        Clear-UserEditor
        Clear-GroupEditor
    }

    $controls.UsersGrid.Add_SelectionChanged({
            Select-User -User $controls.UsersGrid.SelectedItem
        })

    $controls.GroupsGrid.Add_SelectionChanged({
            Select-Group -Group $controls.GroupsGrid.SelectedItem
        })

    $controls.UserNameTextBox.Add_TextChanged({
            Refresh-UserMailPreview
        })

    $controls.UserPrimaryGroupComboBox.ApplyTemplate()
    $primaryGroupEditor = $controls.UserPrimaryGroupComboBox.Template.FindName('PART_EditableTextBox', $controls.UserPrimaryGroupComboBox)
    if ($null -ne $primaryGroupEditor) {
        $primaryGroupEditor.Add_TextChanged({
                Refresh-OtherGroupChoices
            })
    }

    $controls.UserPrimaryGroupComboBox.Add_SelectionChanged({
            Refresh-OtherGroupChoices
        })

    $controls.UserPrimaryGroupComboBox.Add_LostFocus({
            Refresh-OtherGroupChoices
        })

    $controls.UserPrimaryGroupComboBox.Add_DropDownClosed({
            Refresh-OtherGroupChoices
        })

    $controls.BrowseKubeConfigButton.Add_Click({
            $dialog = New-Object Microsoft.Win32.OpenFileDialog
            $dialog.Filter = 'Kubernetes config (*.*)|*.*'
            if ($controls.KubeConfigPathTextBox.Text) {
                $dialog.FileName = $controls.KubeConfigPathTextBox.Text
            }

            if ($dialog.ShowDialog() -ne $true) {
                return
            }

            $controls.KubeConfigPathTextBox.Text = $dialog.FileName
            Refresh-ContextChoices
        })

    $controls.RefreshContextsButton.Add_Click({
            Refresh-ContextChoices
        })

    $controls.NewUserButton.Add_Click({
            $newUid = Get-NextAvailableId -Items $state.Config.Users -PropertyName 'UidNumber' -StartAt 5001
            $defaultGroup = if ($state.Config.Groups.Count -gt 0) { [int]$state.Config.Groups[0].GidNumber } else { 0 }
            $newUser = New-GlauthUserRecord -Name ('user{0}' -f $newUid) -UidNumber $newUid -PrimaryGroup $defaultGroup
            [void]$state.Config.Users.Add($newUser)
            Refresh-UserViews
            Refresh-RawConfigPreview
            $controls.UsersGrid.SelectedIndex = ($state.Config.Users.Count - 1)
            $controls.UsersGrid.SelectedItem = $newUser
            Select-User -User $newUser
            Focus-UserNameField
            if ($defaultGroup -eq 0) {
                $controls.UserPrimaryGroupComboBox.Text = ''
                Set-Status ('Added user template "{0}". Enter a primary group gid or create a role before saving.' -f $newUser.Name)
            }
            else {
                $defaultGroupObject = @($state.Config.Groups | Where-Object { [int]$_.GidNumber -eq $defaultGroup } | Select-Object -First 1)
                if ($defaultGroupObject.Count -gt 0) {
                    $controls.UserPrimaryGroupComboBox.Text = Format-PrimaryGroupChoice -Group $defaultGroupObject[0]
                }
                Set-Status ('Added user template "{0}".' -f $newUser.Name)
            }
        })

    $controls.DeleteUserButton.Add_Click({
            if ($null -eq $controls.UsersGrid.SelectedItem) {
                Set-Status 'Select a user to delete.'
                return
            }

            [void]$state.Config.Users.Remove($controls.UsersGrid.SelectedItem)
            Refresh-UserViews
            Refresh-RawConfigPreview
            Clear-UserEditor
            Set-Status 'Deleted user.'
        })

    $controls.SaveUserButton.Add_Click({
            if ($null -eq $state.CurrentUser) {
                Set-Status 'Select or create a user first.'
                return
            }

            $userName = $controls.UserNameTextBox.Text.Trim()
            $givenName = $controls.UserGivenNameTextBox.Text.Trim()
            $surname = $controls.UserSurnameTextBox.Text.Trim()
            $uidText = $controls.UserUidTextBox.Text.Trim()
            $passSha256 = $controls.UserPassSha256TextBox.Text.Trim()
            $passBcrypt = $controls.UserPassBcryptTextBox.Text.Trim()
            $loginShell = $controls.UserLoginShellTextBox.Text.Trim()
            $homeDir = $controls.UserHomeDirTextBox.Text.Trim()
            $otpSecret = $controls.UserOtpSecretTextBox.Text.Trim()
            $yubiKey = $controls.UserYubiKeyTextBox.Text.Trim()
            $disabled = ($controls.UserDisabledCheckBox.IsChecked -eq $true)

            if ([string]::IsNullOrWhiteSpace($userName)) {
                Set-Status 'User name is required.'
                return
            }

            if ($uidText -notmatch '^\d+$') {
                Set-Status 'UID Number must be numeric.'
                return
            }

            $primaryGroup = $null
            try {
                $primaryGroup = Resolve-PrimaryGroupId -State $state -Controls $controls
            }
            catch {
                Set-Status $_.Exception.Message
                return
            }

            if ($passSha256 -and $passBcrypt) {
                Set-Status 'Use passsha256 or passbcrypt, not both.'
                return
            }

            $otherGroups = @(
                $state.OtherGroupChoices |
                Where-Object { $_.IsSelected } |
                ForEach-Object { [int]$_.GidNumber } |
                Where-Object { $_ -ne [int]$primaryGroup } |
                Select-Object -Unique
            )

            foreach ($user in $state.Config.Users) {
                if ($user -eq $state.CurrentUser) {
                    continue
                }

                if ((Get-ObjectPropertyValue -Object $user -PropertyName 'Name' '') -eq $userName) {
                    Set-Status 'User names must be unique.'
                    return
                }

                if ([int](Get-ObjectPropertyValue -Object $user -PropertyName 'UidNumber' 0) -eq [int]$uidText) {
                    Set-Status 'UID numbers must be unique.'
                    return
                }
            }

            if ($null -eq (Get-ObjectPropertyValue -Object $state.CurrentUser -PropertyName 'Name') -or
                $null -eq (Get-ObjectPropertyValue -Object $state.CurrentUser -PropertyName 'UidNumber') -or
                $null -eq (Get-ObjectPropertyValue -Object $state.CurrentUser -PropertyName 'PrimaryGroup')) {
                $selectedIndex = $controls.UsersGrid.SelectedIndex
                $replacementUser = New-GlauthUserRecord
                if ($selectedIndex -ge 0 -and $selectedIndex -lt $state.Config.Users.Count) {
                    $state.Config.Users[$selectedIndex] = $replacementUser
                }
                else {
                    [void]$state.Config.Users.Add($replacementUser)
                }

                $state.CurrentUser = $replacementUser
            }

            $state.CurrentUser.Name = $userName
            $state.CurrentUser.GivenName = $givenName
            $state.CurrentUser.Surname = $surname
            $derivedMail = Get-GlauthDerivedMailAddress -Config $state.Config -UserName $state.CurrentUser.Name
            if ([string]::IsNullOrWhiteSpace($derivedMail)) {
                Set-Status 'Could not derive email from backend.baseDN.'
                return
            }

            $state.CurrentUser.Mail = $derivedMail
            $state.CurrentUser.UidNumber = [int]$uidText
            $state.CurrentUser.PrimaryGroup = [int]$primaryGroup
            $state.CurrentUser.OtherGroups = [int[]]@($otherGroups)
            $state.CurrentUser.LoginShell = $loginShell
            $state.CurrentUser.HomeDir = $homeDir
            $state.CurrentUser.PassSha256 = $passSha256
            $state.CurrentUser.PassBcrypt = $passBcrypt
            $state.CurrentUser.OtpSecret = $otpSecret
            $state.CurrentUser.YubiKey = $yubiKey
            $state.CurrentUser.Disabled = $disabled

            Refresh-UserViews
            Refresh-UserMailPreview
            Refresh-RawConfigPreview
            $controls.UsersGrid.SelectedItem = $state.CurrentUser
            Set-Status ('Saved user "{0}".' -f $userName)
        })

    $controls.GeneratePasswordHashButton.Add_Click({
            if ([string]::IsNullOrEmpty($controls.UserPasswordBox.Password)) {
                Set-Status 'Enter a password to generate passbcrypt.'
                return
            }

            try {
                $controls.UserPassBcryptTextBox.Text = ConvertTo-GlauthBcryptHash -Password $controls.UserPasswordBox.Password
                $controls.UserPassSha256TextBox.Text = ''
                $controls.UserPasswordBox.Password = ''
                Set-Status 'Generated passbcrypt and cleared passsha256.'
            }
            catch {
                Set-Status $_.Exception.Message
            }
        })

    $controls.NewGroupButton.Add_Click({
            $newGid = Get-NextAvailableId -Items $state.Config.Groups -PropertyName 'GidNumber' -StartAt 5501
            $newGroup = New-GlauthGroupRecord -Name ('role{0}' -f $newGid) -GidNumber $newGid
            [void]$state.Config.Groups.Add($newGroup)
            Refresh-GroupViews
            Refresh-RawConfigPreview
            $controls.GroupsGrid.SelectedItem = $newGroup
            Select-Group -Group $newGroup
            Set-Status ('Added role template "{0}".' -f $newGroup.Name)
        })

    $controls.DeleteGroupButton.Add_Click({
            if ($null -eq $controls.GroupsGrid.SelectedItem) {
                Set-Status 'Select a role to delete.'
                return
            }

            $groupToDelete = $controls.GroupsGrid.SelectedItem
            foreach ($user in $state.Config.Users) {
                if ([int]$user.PrimaryGroup -eq [int]$groupToDelete.GidNumber -or @($user.OtherGroups) -contains [int]$groupToDelete.GidNumber) {
                    Set-Status ('Role "{0}" is still referenced by user "{1}".' -f $groupToDelete.Name, $user.Name)
                    return
                }
            }

            foreach ($group in $state.Config.Groups) {
                if ($group -ne $groupToDelete -and @($group.IncludeGroups) -contains [int]$groupToDelete.GidNumber) {
                    Set-Status ('Role "{0}" is still referenced by role "{1}".' -f $groupToDelete.Name, $group.Name)
                    return
                }
            }

            [void]$state.Config.Groups.Remove($groupToDelete)
            Refresh-GroupViews
            Refresh-RawConfigPreview
            Clear-GroupEditor
            Set-Status 'Deleted role.'
        })

    $controls.SaveGroupButton.Add_Click({
            if ($null -eq $state.CurrentGroup) {
                Set-Status 'Select or create a role first.'
                return
            }

            if ([string]::IsNullOrWhiteSpace($controls.GroupNameTextBox.Text)) {
                Set-Status 'Role name is required.'
                return
            }

            if ($controls.GroupGidTextBox.Text -notmatch '^\d+$') {
                Set-Status 'GID Number must be numeric.'
                return
            }

            $includeGroups = @()
            try {
                $includeGroups = ConvertFrom-IdListString -Text $controls.GroupIncludeGroupsTextBox.Text
            }
            catch {
                Set-Status $_.Exception.Message
                return
            }

            foreach ($group in $state.Config.Groups) {
                if ($group -eq $state.CurrentGroup) {
                    continue
                }

                if ($group.Name -eq $controls.GroupNameTextBox.Text.Trim()) {
                    Set-Status 'Role names must be unique.'
                    return
                }

                if ([int]$group.GidNumber -eq [int]$controls.GroupGidTextBox.Text) {
                    Set-Status 'GID numbers must be unique.'
                    return
                }
            }

            $state.CurrentGroup.Name = $controls.GroupNameTextBox.Text.Trim()
            $state.CurrentGroup.GidNumber = [int]$controls.GroupGidTextBox.Text
            $state.CurrentGroup.IncludeGroups = [int[]]@($includeGroups)
            $state.CurrentGroup.IncludeGroupsDisplay = ConvertTo-IdListString -Values $includeGroups

            Refresh-GroupViews
            Refresh-RawConfigPreview
            $controls.GroupsGrid.SelectedItem = $state.CurrentGroup
            Set-Status ('Saved role "{0}".' -f $state.CurrentGroup.Name)
        })

    $controls.RefreshPreviewButton.Add_Click({
            Refresh-RawConfigPreview
            Set-Status 'Preview refreshed.'
        })

    $controls.LoadFileButton.Add_Click({
            $dialog = New-Object Microsoft.Win32.OpenFileDialog
            $dialog.Filter = 'GLAuth config (*.cfg;*.toml)|*.cfg;*.toml|All files (*.*)|*.*'
            if ($dialog.ShowDialog() -ne $true) {
                return
            }

            $configText = Get-Content -LiteralPath $dialog.FileName -Raw
            Load-ConfigText -ConfigText $configText -SourcePath $dialog.FileName
            Set-Status ('Loaded config from file "{0}".' -f $dialog.FileName)
        })

    $controls.SaveFileButton.Add_Click({
            $dialog = New-Object Microsoft.Win32.SaveFileDialog
            $dialog.Filter = 'GLAuth config (*.cfg)|*.cfg|TOML (*.toml)|*.toml|All files (*.*)|*.*'
            if ($state.SourcePath) {
                $dialog.FileName = $state.SourcePath
            }

            if ($dialog.ShowDialog() -ne $true) {
                return
            }

            Sync-GlauthUserMailAddresses -Config $state.Config
            [System.IO.File]::WriteAllText($dialog.FileName, (ConvertTo-GlauthConfigText -Config $state.Config), [System.Text.Encoding]::UTF8)
            $state.SourcePath = $dialog.FileName
            Set-Status ('Saved config to file "{0}".' -f $dialog.FileName)
        })

    $controls.LoadClusterButton.Add_Click({
            if ([string]::IsNullOrWhiteSpace($controls.NamespaceTextBox.Text) -or [string]::IsNullOrWhiteSpace($controls.ConfigMapTextBox.Text) -or [string]::IsNullOrWhiteSpace($controls.DataKeyTextBox.Text)) {
                Set-Status 'Namespace, ConfigMap, and Data Key are required.'
                Show-ErrorMessage -Title 'Load from Cluster' -Message 'Namespace, ConfigMap, and Data Key are required.'
                return
            }

            try {
                $result = Get-GlauthConfigFromCluster -KubeConfigPath $controls.KubeConfigPathTextBox.Text.Trim() -Context $controls.ContextComboBox.Text.Trim() -Namespace $controls.NamespaceTextBox.Text.Trim() -ConfigMapName $controls.ConfigMapTextBox.Text.Trim() -DataKey $controls.DataKeyTextBox.Text.Trim()
                Load-ConfigText -ConfigText $result.ConfigText -ConfigMapObject $result.ConfigMapObject
                $message = 'Loaded config from ConfigMap "{0}/{1}" with {2} user(s) and {3} role(s).' -f $controls.NamespaceTextBox.Text.Trim(), $controls.ConfigMapTextBox.Text.Trim(), $state.Config.Users.Count, $state.Config.Groups.Count
                Set-Status $message
                Show-OperationMessage -Title 'Load from Cluster' -Message $message
            }
            catch {
                Set-Status $_.Exception.Message
                Show-ErrorMessage -Title 'Load from Cluster' -Message $_.Exception.Message
            }
        })

    $controls.SaveClusterButton.Add_Click({
            if ([string]::IsNullOrWhiteSpace($controls.NamespaceTextBox.Text) -or [string]::IsNullOrWhiteSpace($controls.ConfigMapTextBox.Text) -or [string]::IsNullOrWhiteSpace($controls.DataKeyTextBox.Text)) {
                Set-Status 'Namespace, ConfigMap, and Data Key are required.'
                Show-ErrorMessage -Title 'Save to Cluster' -Message 'Namespace, ConfigMap, and Data Key are required.'
                return
            }

            try {
                Sync-GlauthUserMailAddresses -Config $state.Config
                $updatedConfigMapObject = Save-GlauthConfigToCluster -KubeConfigPath $controls.KubeConfigPathTextBox.Text.Trim() -Context $controls.ContextComboBox.Text.Trim() -Namespace $controls.NamespaceTextBox.Text.Trim() -ConfigMapName $controls.ConfigMapTextBox.Text.Trim() -DataKey $controls.DataKeyTextBox.Text.Trim() -ConfigText (ConvertTo-GlauthConfigText -Config $state.Config) -ConfigMapObject $state.ConfigMapObject
                $state.ConfigMapObject = $updatedConfigMapObject
                $message = 'Saved config to ConfigMap "{0}/{1}".' -f $controls.NamespaceTextBox.Text.Trim(), $controls.ConfigMapTextBox.Text.Trim()
                Set-Status $message
                Show-OperationMessage -Title 'Save to Cluster' -Message $message
            }
            catch {
                Set-Status $_.Exception.Message
                Show-ErrorMessage -Title 'Save to Cluster' -Message $_.Exception.Message
            }
        })

    $defaultKubeConfigPath = Join-Path -Path $HOME -ChildPath '.kube\config'
    if (Test-Path -LiteralPath $defaultKubeConfigPath) {
        $controls.KubeConfigPathTextBox.Text = $defaultKubeConfigPath
        Refresh-ContextChoices
    }

    Refresh-GroupViews
    Refresh-UserViews
    Refresh-RawConfigPreview
    Clear-UserEditor
    Clear-GroupEditor
    Set-Status 'Ready. Load a file or ConfigMap to begin.'

    [void]$window.ShowDialog()
}

Export-ModuleMember -Function Show-GlauthUserManagerWindow
