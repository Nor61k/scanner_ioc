/*
    YARA rules for shellcode and suspicious pattern detection in memory
*/

rule generic_shellcode {
    meta:
        description = "Generic shellcode detection"
        author = "RuScan"
        severity = "high"
        tags = ["shellcode", "injection"]

    strings:
        // NOP sled
        $nop1 = { 90 90 90 90 90 90 90 90 }
        $nop2 = { 66 90 66 90 66 90 66 90 }
        
        // Typical shellcode instructions
        $push_call = { 68 ?? ?? ?? ?? E8 }
        $get_eip = { E8 00 00 00 00 }
        $api_hashing = { 33 C0 66 B8 ?? ?? }
        
        // API strings
        $kernel32 = "kernel32.dll" nocase ascii wide
        $loadlib = "LoadLibraryA" ascii
        $getproc = "GetProcAddress" ascii

    condition:
        any of ($nop*) or
        any of ($push_call, $get_eip, $api_hashing) or
        all of ($kernel32, $loadlib, $getproc)
}

rule process_injection {
    meta:
        description = "Process injection detection"
        author = "RuScan"
        severity = "high"
        tags = ["injection", "process"]

    strings:
        // Injection APIs
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtCreateThreadEx" ascii
        $api5 = "RtlCreateUserThread" ascii
        
        // Memory access flags
        $mem1 = { 00 30 00 00 }
        $mem2 = { 00 10 00 00 }
        
        // Suspicious patterns
        $pattern1 = { 48 83 EC ?? 48 8B ?? ?? ?? 48 8B }
        $pattern2 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 }

    condition:
        3 of ($api*) or
        all of ($mem*) or
        any of ($pattern*)
}

rule powershell_shellcode {
    meta:
        description = "PowerShell shellcode detection"
        author = "RuScan"
        severity = "high"
        tags = ["powershell", "shellcode"]

    strings:
        // PowerShell commands
        $cmd1 = "[System.Runtime.InteropServices.Marshal]::Copy" ascii wide
        $cmd2 = "VirtualAlloc" ascii wide
        $cmd3 = "0xfc,0x48,0x83,0xe4" ascii wide
        
        // Suspicious functions
        $func1 = "New-Object System.IO.MemoryStream" ascii wide
        $func2 = "System.Runtime.InteropServices.RuntimeInformation" ascii wide

    condition:
        2 of ($cmd*) or
        all of ($func*)
}

rule reflective_dll {
    meta:
        description = "Reflective DLL loading detection"
        author = "RuScan"
        severity = "high"
        tags = ["dll", "injection"]

    strings:
        // Characteristic strings
        $refl1 = "ReflectiveLoader" ascii
        $refl2 = "reflective_dll" ascii
        
        // PE header in memory
        $mz = "MZ" ascii
        $pe = "PE" ascii
        
        // Sections
        $sec1 = ".text" ascii
        $sec2 = ".rdata" ascii
        $sec3 = ".data" ascii
        
        // Loading APIs
        $api1 = "LoadLibraryA" ascii
        $api2 = "GetProcAddress" ascii
        $api3 = "VirtualAlloc" ascii

    condition:
        ($mz at 0 and $pe) and
        2 of ($sec*) and
        (any of ($refl*) or all of ($api*))
}

rule hollowing_detection {
    meta:
        description = "Process Hollowing detection"
        author = "RuScan"
        severity = "high"
        tags = ["hollowing", "injection"]

    strings:
        // Process Hollowing APIs
        $api1 = "NtUnmapViewOfSection" ascii
        $api2 = "ZwUnmapViewOfSection" ascii
        $api3 = "NtWriteVirtualMemory" ascii
        $api4 = "SetThreadContext" ascii
        
        // Process creation flags
        $flag1 = { 08 00 00 00 }
        
        // Memory manipulation patterns
        $mem1 = { 48 8B 45 ?? 48 8B 40 ?? }
        $mem2 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 }

    condition:
        2 of ($api*) and
        ($flag1 or any of ($mem*))
}

rule windows_shellcode {
    meta:
        description = "Windows shellcode detection"
        author = "RuScan"
        date = "2024-06-04"
        
    strings:
        $api1 = "LoadLibraryA" ascii wide
        $api2 = "GetProcAddress" ascii wide
        $api3 = "VirtualAlloc" ascii wide
        $api4 = "VirtualProtect" ascii wide
        
        $shellcode1 = { 31 ?? 50 50 50 }
        $shellcode2 = { 68 ?? ?? ?? ?? }
        $shellcode3 = { FF 75 ?? }
        $shellcode4 = { FF 55 ?? }
        
    condition:
        (2 of ($api*)) and (2 of ($shellcode*))
} 