/*
Правила для сканирования памяти процессов
*/

rule Memory_Shellcode {
    meta:
        description = "Обнаружение шелл-кода в памяти"
        author = "RuScan"
        severity = "critical"
        
    strings:
        $shellcode1 = { 55 8B EC } // push ebp; mov ebp, esp
        $shellcode2 = { 33 C0 } // xor eax, eax
        $shellcode3 = { 89 E5 } // mov ebp, esp
        $shellcode4 = { 31 C0 } // xor eax, eax
        $shellcode5 = { CD 80 } // int 0x80
        $shellcode6 = { FF D0 } // call eax
        
    condition:
        3 of them
}

rule Memory_Injection {
    meta:
        description = "Обнаружение внедрения кода в память"
        author = "RuScan"
        severity = "critical"
        
    strings:
        $mz = "MZ"
        $pe = "PE"
        $api1 = "VirtualAlloc"
        $api2 = "VirtualProtect"
        $api3 = "WriteProcessMemory"
        $api4 = "CreateRemoteThread"
        $api5 = "LoadLibrary"
        $api6 = "GetProcAddress"
        
    condition:
        ($mz at 0 or $pe) and 2 of ($api*)
}

rule Memory_Keylogger {
    meta:
        description = "Обнаружение кейлоггеров в памяти"
        author = "RuScan"
        severity = "high"
        
    strings:
        $api1 = "GetAsyncKeyState"
        $api2 = "GetKeyboardState"
        $api3 = "SetWindowsHookEx"
        $api4 = "RegisterHotKey"
        $str1 = "keylog" nocase
        $str2 = "hook" nocase
        
    condition:
        2 of ($api*) or (1 of ($api*) and 1 of ($str*))
}

rule Memory_Credentials {
    meta:
        description = "Обнаружение сбора учетных данных в памяти"
        author = "RuScan"
        severity = "high"
        
    strings:
        $api1 = "LsaEnumerateLogonSessions"
        $api2 = "SamEnumerateUsers"
        $api3 = "CredEnumerate"
        $str1 = "password" nocase
        $str2 = "login" nocase
        $str3 = "credential" nocase
        
    condition:
        1 of ($api*) and 1 of ($str*)
}

rule Memory_Ransomware {
    meta:
        description = "Обнаружение признаков шифровальщиков в памяти"
        author = "RuScan"
        severity = "critical"
        
    strings:
        $api1 = "CryptEncrypt"
        $api2 = "CryptAcquireContext"
        $api3 = "BCryptEncrypt"
        $str1 = ".encrypted" nocase
        $str2 = "ransom" nocase
        $str3 = "bitcoin" nocase
        $str4 = "payment" nocase
        
    condition:
        2 of ($api*) or (1 of ($api*) and 2 of ($str*))
} 