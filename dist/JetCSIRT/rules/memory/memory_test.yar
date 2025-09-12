rule Mimikatz_In_Memory
{
    meta:
        description = "Обнаружение строки mimikatz в памяти"
        author = "JetCSIRT"
        reference = "https://github.com/gentilkiwi/mimikatz"
    strings:
        $mz = "mimikatz"
    condition:
        $mz
}

rule Suspicious_PowerShell_Memory
{
    meta:
        description = "Подозрительные PowerShell команды в памяти"
        author = "JetCSIRT"
    strings:
        $ps1 = "Invoke-Expression"
        $ps2 = "IEX"
        $ps3 = "FromBase64String"
    condition:
        any of ($ps*)
}

rule Meterpreter_Memory
{
    meta:
        description = "Meterpreter shellcode в памяти"
        author = "JetCSIRT"
    strings:
        $m1 = "meterpreter"
        $m2 = "core_channel_open"
        $m3 = "core_channel_write"
    condition:
        any of ($m*)
} 