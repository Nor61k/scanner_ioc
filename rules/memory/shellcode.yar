/*
    Правила YARA для обнаружения шелл-кода и подозрительных паттернов в памяти
*/

rule generic_shellcode {
    meta:
        description = "Обнаружение шелл-кода по характерным признакам"
        author = "RuScan"
        severity = "high"
        tags = ["shellcode", "injection"]

    strings:
        // NOP sled
        $nop1 = { 90 90 90 90 90 90 90 90 }
        $nop2 = { 66 90 66 90 66 90 66 90 }
        
        // Типичные инструкции шелл-кода
        $push_call = { 68 ?? ?? ?? ?? E8 }
        $get_eip = { E8 00 00 00 00 }
        $api_hashing = { 33 C0 66 B8 ?? ?? }
        
        // Строки для поиска API
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
        description = "Обнаружение внедрения кода в процессы"
        author = "RuScan"
        severity = "high"
        tags = ["injection", "process"]

    strings:
        // API для внедрения кода
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtCreateThreadEx" ascii
        $api5 = "RtlCreateUserThread" ascii
        
        // Флаги доступа к памяти
        $mem1 = { 00 30 00 00 } // PAGE_EXECUTE_READWRITE
        $mem2 = { 00 10 00 00 } // PAGE_EXECUTE
        
        // Подозрительные паттерны
        $pattern1 = { 48 83 EC ?? 48 8B ?? ?? ?? 48 8B }
        $pattern2 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 }

    condition:
        3 of ($api*) or
        all of ($mem*) or
        any of ($pattern*)
}

rule powershell_shellcode {
    meta:
        description = "Обнаружение шелл-кода в PowerShell"
        author = "RuScan"
        severity = "high"
        tags = ["powershell", "shellcode"]

    strings:
        // PowerShell команды
        $cmd1 = "[System.Runtime.InteropServices.Marshal]::Copy" ascii wide
        $cmd2 = "VirtualAlloc" ascii wide
        $cmd3 = "0xfc,0x48,0x83,0xe4" ascii wide
        
        // Base64 encoded shellcode
        // (удалено правило $b64 из-за синтаксиса [ ... ])
        
        // Подозрительные функции
        $func1 = "New-Object System.IO.MemoryStream" ascii wide
        $func2 = "System.Runtime.InteropServices.RuntimeInformation" ascii wide

    condition:
        2 of ($cmd*) or
        all of ($func*)
}

rule reflective_dll {
    meta:
        description = "Обнаружение рефлективной загрузки DLL"
        author = "RuScan"
        severity = "high"
        tags = ["dll", "injection"]

    strings:
        // Характерные строки
        $refl1 = "ReflectiveLoader" ascii
        $refl2 = "reflective_dll" ascii
        
        // PE заголовок в памяти
        $mz = "MZ" ascii
        $pe = "PE" ascii
        
        // Секции
        $sec1 = ".text" ascii
        $sec2 = ".rdata" ascii
        $sec3 = ".data" ascii
        
        // API для загрузки
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
        description = "Обнаружение Process Hollowing"
        author = "RuScan"
        severity = "high"
        tags = ["hollowing", "injection"]

    strings:
        // API для Process Hollowing
        $api1 = "NtUnmapViewOfSection" ascii
        $api2 = "ZwUnmapViewOfSection" ascii
        $api3 = "NtWriteVirtualMemory" ascii
        $api4 = "SetThreadContext" ascii
        
        // Флаги создания процесса
        $flag1 = { 08 00 00 00 } // CREATE_SUSPENDED
        
        // Паттерны работы с памятью
        $mem1 = { 48 8B 45 ?? 48 8B 40 ?? }
        $mem2 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 }

    condition:
        2 of ($api*) and
        ($flag1 or any of ($mem*))
}

rule windows_shellcode {
    meta:
        description = "Детектирование шелл-кода Windows"
        author = "RuScan"
        date = "2024-06-04"
        
    strings:
        $api1 = "LoadLibraryA" ascii wide
        $api2 = "GetProcAddress" ascii wide
        $api3 = "VirtualAlloc" ascii wide
        $api4 = "VirtualProtect" ascii wide
        
        $shellcode1 = { 31 ?? 50 50 50 }  // xor reg, reg + push sequence
        $shellcode2 = { 68 ?? ?? ?? ?? }   // push immediate
        $shellcode3 = { FF 75 ?? }         // push ebp+XX
        $shellcode4 = { FF 55 ?? }         // call ebp+XX
        
    condition:
        (2 of ($api*)) and (2 of ($shellcode*))
} 