<#
  idm_keygen.ps1 - generate and validate Internet Download Manager serials.

  Reversed from IDMan.exe 6.43.15.2 (sha256 E3FC655A...) by static disassembly of
  the registration dialog's OnOk handler (RVA 0x122910) and its five-character
  block decoder (RVA 0x1218F0). The decision the dialog makes is entirely local:
  no key, no signature, no server, no hash - a length check, three dashes and
  four divisibility constraints. A serial this tool accepts is accepted by the
  dialog; the dialog then writes it to the registry, and the startup check
  (RVA 0x050B40) only re-checks the format, so the serial survives a restart.

  Usage:
    .\idm_keygen.ps1                                     five serials on stdout
    .\idm_keygen.ps1 -Count 1                            one serial
    .\idm_keygen.ps1 -Validate XXXXX-XXXXX-XXXXX-XXXXX   audit a serial
    .\idm_keygen.ps1 -SelfTest                           reference vectors + round-trips
#>
[CmdletBinding(DefaultParameterSetName = 'Generate')]
param(
    [Parameter(ParameterSetName = 'Validate', Position = 0, Mandatory = $true)]
    [string]$Validate,

    [Parameter(ParameterSetName = 'Generate')]
    [ValidateRange(1, 200)]
    [int]$Count = 5,

    [Parameter(ParameterSetName = 'SelfTest')]
    [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'

# Alphabet written by OnOk at RVA 0x122954 - a shuffled 0-9 A-Z, index 0..35.
$script:Charset = '2YOPB3AQCVUXMNRS97WE0IZD4KLFGHJ8165T'
# Decoder: value = value * 0x25 + index (RVA 0x121921), five iterations.
$script:Base = 37
# Block order left to right, one modulus each (OnOk RVA 0x122910).
$script:Moduli = @(43, 23, 17, 53)
$script:Layout = @(0, 6, 12, 18)

function ConvertTo-IdmBlock {
    param([Parameter(Mandatory = $true)][int]$Modulus)

    while ($true) {
        $digits = @(0, 0, 0, 0, 0)
        $value = [int64]0
        for ($i = 0; $i -lt 5; $i++) {
            $digits[$i] = Get-Random -Minimum 0 -Maximum $script:Charset.Length
            $value = $value * $script:Base + $digits[$i]
        }
        if ($value -gt 0 -and ($value % $Modulus) -eq 0) {
            return [pscustomobject]@{
                Text  = -join ($digits | ForEach-Object { $script:Charset[$_] })
                Value = $value
            }
        }
    }
}

function ConvertFrom-IdmBlock {
    param([Parameter(Mandatory = $true)][string]$Text)

    $value = [int64]0
    foreach ($glyph in $Text.ToCharArray()) {
        $index = $script:Charset.IndexOf($glyph)
        if ($index -lt 0) { return $null }
        $value = $value * $script:Base + $index
    }
    return $value
}

function Test-IdmSerial {
    param([Parameter(Mandatory = $true)][string]$Text)

    $problems = @()
    $serial = $Text.Trim().ToUpperInvariant()

    if ($serial.Length -ne 23) {
        $problems += "length $($serial.Length), expected 23"
    }
    else {
        foreach ($index in 5, 11, 17) {
            if ($serial[$index] -ne '-') {
                $problems += "index $index is '$($serial[$index])', expected '-'"
            }
        }
    }

    $blocks = @()
    if ($problems.Count -eq 0) {
        for ($i = 0; $i -lt 4; $i++) {
            $text = $serial.Substring($script:Layout[$i], 5)
            $modulus = $script:Moduli[$i]
            $value = ConvertFrom-IdmBlock -Text $text
            if ($null -eq $value) {
                $problems += "block ${i} '$text' carries a glyph outside the 36-glyph alphabet"
            }
            elseif ($value -eq 0) {
                $problems += "block ${i} '$text' decodes to 0"
            }
            elseif ($value % $modulus -ne 0) {
                $problems += "block ${i} '$text' = $value, not a multiple of $modulus"
            }
            else {
                $blocks += [pscustomobject]@{
                    Block = $i; Text = $text; Value = $value; Modulus = $modulus
                }
            }
        }
    }

    [pscustomobject]@{
        Valid    = ($problems.Count -eq 0)
        Serial   = $serial
        Blocks   = $blocks
        Problems = $problems
    }
}

function New-IdmSerial {
    $parts = foreach ($modulus in $script:Moduli) {
        (ConvertTo-IdmBlock -Modulus $modulus).Text
    }
    ($parts -join '-')
}

function Show-IdmSerial {
    param([Parameter(Mandatory = $true)][object]$Result)

    if ($Result.Valid) {
        Write-Output ('  format    {0} chars, dashes at 5/11/17      OK' -f $Result.Serial.Length)
        foreach ($block in $Result.Blocks) {
            Write-Output ('  block {0}   {1}  ->  {2,8}  %{3} == 0  OK' -f
                $block.Block, $block.Text, $block.Value, $block.Modulus)
        }
        Write-Output ('  result    VALID  {0}' -f $Result.Serial)
    }
    else {
        foreach ($problem in $Result.Problems) {
            Write-Output ('  FAIL      {0}' -f $problem)
        }
        Write-Output ('  result    INVALID  {0}' -f $Result.Serial)
    }
}

function Invoke-SelfTest {
    $failed = 0

    $vectors = @(
        @{ Text = '222YA-2222D-22227-222Y9'; Valid = $true;  Why = '43,23,17,53 exactly' }
        @{ Text = '222YA-2222D-22227-222Y8'; Valid = $false; Why = 'block 3 = 68, 68 % 53 = 15' }
        @{ Text = '22222-22222-22222-22222'; Valid = $false; Why = 'every block decodes to 0' }
        @{ Text = '2222A-2222A-2222A-2222A'; Valid = $false; Why = 'value 6 in every block' }
        @{ Text = '222Y!-2222D-22227-222Y9'; Valid = $false; Why = 'glyph outside the alphabet' }
        @{ Text = '222YA_2222D-22227-222Y9'; Valid = $false; Why = 'dash at index 5 missing' }
        @{ Text = '222YA-2222D-22227';       Valid = $false; Why = 'too short' }
        @{ Text = '  222ya-2222d-22227-222y9  '; Valid = $true; Why = 'trim + lowercase accepted' }
    )

    foreach ($vector in $vectors) {
        $result = Test-IdmSerial -Text $vector.Text
        if ($result.Valid -eq $vector.Valid) {
            Write-Output ('  PASS  {0,-28} {1}' -f $vector.Text.Trim(), $vector.Why)
        }
        else {
            $failed++
            Write-Output ('  FAIL  {0,-28} expected {1}, got {2}' -f
                $vector.Text.Trim(), $vector.Valid, $result.Valid)
        }
    }

    $roundTrips = 500
    for ($i = 0; $i -lt $roundTrips; $i++) {
        $serial = New-IdmSerial
        $result = Test-IdmSerial -Text $serial
        if (-not $result.Valid) {
            $failed++
            Write-Output ('  FAIL  round-trip {0} -> {1}' -f $serial, ($result.Problems -join '; '))
            break
        }
    }
    if ($failed -eq 0) {
        Write-Output ('  PASS  {0} generated serials round-trip' -f $roundTrips)
    }

    $total = $vectors.Count + 1
    Write-Output ('selftest {0}/{1} passed' -f ($total - $failed), $total)
    if ($failed -gt 0) { exit 1 }
}

switch ($PSCmdlet.ParameterSetName) {
    'Validate' {
        Show-IdmSerial -Result (Test-IdmSerial -Text $Validate)
    }
    'SelfTest' {
        Invoke-SelfTest
    }
    default {
        for ($i = 0; $i -lt $Count; $i++) {
            $serial = New-IdmSerial
            $result = Test-IdmSerial -Text $serial
            if (-not $result.Valid) {
                throw ("generated serial failed its own validator: {0} - {1}" -f
                    $serial, ($result.Problems -join '; '))
            }
            Write-Output $serial
        }
    }
}
