# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os


_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

CUCKOO_VERSION = "1.0"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004

# Changed: Added stop event, AV consts and diff logics consts.

STOP_EVENT = "stopevent"

# Anti-Virus names strings
AV_NAMES = [
        "AntiVirus",
        "McAfee",
        "Symantec",
        "Kaspersky",
        "ZoneLabs",
        "Panda",
        "Sophos",
        "Ahnlab",
        "BitDefender",
        "Norton",
        "NetLimiter",
        "Avira",
        "Avast",
        "Agnitum",
        "antivir",
        "baidu",
        "virobot",
        "totaldefense",
        "thehacker"
]

# AntiVirus process names list.
# Short names include ".exe" to avoid false positives.
AV_PROCESS_NAMES = [
        "avciman",
        "avengine",
        "avp.exe",
        "ca.exe",
        "caissdt",
        "cavrid",
        "cavtray",
        "ccapp.exe",
        "ccetvmgr",
        "ccproxy",
        "ccsetmgr",
        "dpasnt",
        "firewallntservice",
        "fsaw.exe",
        "fsguidll",
        "fsm32.exe",
        "fspex.exe",
        "hsockpe",
        "isafe",
        "kav.exe",
        "kavpf.exe",
        "mcagent",
        "mcdetect",
        "mcshield",
        "mctskshd",
        "mcupdate",
        "mcupdmgr",
        "mcvsescn",
        "mcvsshld",
        "mpeng",
        "mpfagent",
        "mpfservice",
        "mpftray",
        "msascui",
        "mscifapp",
        "mscorsvw",
        "msfwsvc",
	 "mskagent",
        "msksrvr",
        "msmpsvc",
        "mxtask",
        "navapsvc",
        "nscsrvce",
        "oasclnt",
        "pavfnsvr",
        "pavprsrv",
        "pavsrv51",
        "pnmsrv",
        "psimsvc",
        "pskmssvc",
        "sdhelp",
        "sndsrvc",
        "spbbcsvc",
        "spysweeper",
        "spysweeperui",
        "srvload",
        "ssu.exe",
        "swdoctor",
        "symlcsvc",
        "tpsrv",
        "tsantispy",
        "vir.exe",
        "vrfwsvc",
        "vrmonnt",
        "vrmonsvc",
        "vsmon",
        "wad-watch",
        "wdfdataservice",
        "webproxy",
        "webrootdesktopfirewall",
        "winssnotify",
        "zlclient",
]

PSXSCAN_RULES = [

                        {"pslist" : "True",
                        "psscan" : "True",
                        "thrdproc"  : "False"
                        },
                        {"pslist" : "False",
                        "psscan" : "False",
                        }

                ]
AUTOSTART_REG_KEYS = [
r"software\microsoft\windows\currentversion\run",
r"software\microsoft\windows\currentversion\runonce",
r"software\microsoft\windows\currentversion\runservices",
r"software\microsoft\windows\currentversion\runservicesonce",
r"software\microsoft\windows\currentversion\run",
r"software\microsoft\windows\currentversion\runonce",
r"software\microsoft\windows\currentversion\runonce\setup",
r".default\software\microsoft\windows\currentversion\run",
r".default\software\microsoft\windows\currentversion\runonce",
r"software\microsoft\windows NT\currentversion\Winlogon ",
r"software\microsoft\Active setup\Installed Components",
r"system\currentcontrolset\services\vxd",
r"control panel\desktop control panel\desktop",
r"system\currentcontrolset\control\session manager",
r"vbsfile\shell\open\command",
r"vbefile\shell\open\command",
r"jsfile\shell\open\command",
r"jsefile\shell\open\command",
r"wshfile\shell\open\command",
r"wsffile\shell\open\command",
r"exefile\shell\open\command",
r"comfile\shell\open\command",
r"batfile\shell\open\command",
r"scrfile\shell\open\command",
r"piffile\shell\open\command",
r"system\currentcontrolset\services",
r"system\control\wow\cmdline",
r"system\control\wow\wowcmdline",
r"software\microsoft\windows NT\currentversion\winlogon\userinit",
r"software\microsoft\windows\currentversion\shellserviceobjectdelayload",
r"software\microsoft\windows NT\currentversion\windows\run",
r"software\microsoft\windows NT\currentversion\windows\load",
r"software\microsoft\windows\currentversion\policies\explorer\run",
r"software\microsoft\windows\currentversion\policies\explorer\run",
r"services\winsock2\parameters",
]
WIN_KERNEL_MODULES = [
        "mouhid.sys",
        "hidusb.sys",
        "hidclass.sys",
]

WIN_SERVICES = [
        "kmixer",
        "rsdl2tp",
        "ndiswan",
        "ndistapi",
]

PAGE_PROTECTIONS = {
        1 : 'PAGE_NOACCESS',
        2 : 'PAGE_READONLY',
        4 : 'PAGE_READWRITE',
        8 : 'PAGE_WRITECOPY',
        16 : 'PAGE_EXECUTE',
        32 : 'PAGE_EXECUTE_READ',
        64 : 'PAGE_EXECUTE_READWRITE',
        128 : 'PAGE_EXECUTE_WRITECOPY',
        257 : 'PAGE_GUARD | PAGE_NOACCESS',
        258 : 'PAGE_GUARD | PAGE_READONLY',
        260 : 'PAGE_GUARD | PAGE_READWRITE',
        264 : 'PAGE_GUARD | PAGE_WRITECOPY',
        278 : 'PAGE_GUARD | PAGE_EXECUTE',
        288 : 'PAGE_GUARD | PAGE_EXECUTE_READ',
        320 : 'PAGE_GUARD | PAGE_EXECUTE_READWRITE',
        384 : 'PAGE_GUARD | PAGE_EXECUTE_WRITECOPY',
        513 : 'PAGE_NOCACHE | PAGE_NOACCESS',
        514 : 'PAGE_NOCACHE | PAGE_READONLY',
        516 : 'PAGE_NOCACHE | PAGE_READWRITE',
        520 : 'PAGE_NOCACHE | PAGE_WRITECOPY',
        528 : 'PAGE_NOCACHE | PAGE_EXECUTE',
        544 : 'PAGE_NOCACHE | PAGE_EXECUTE_READ',
        576 : 'PAGE_NOCACHE | PAGE_EXECUTE_READWRITE',
        640 : 'PAGE_NOCACHE | PAGE_EXECUTE_WRITECOPY',
        1025 : 'PAGE_WRITECOMBINE | PAGE_NOACCESS',
        1026 : 'PAGE_WRITECOMBINE | PAGE_READONLY',
        1028 : 'PAGE_WRITECOMBINE | PAGE_READWRITE',
        1032 : 'PAGE_WRITECOMBINE | PAGE_WRITECOPY',
        1040 : 'PAGE_WRITECOMBINE | PAGE_EXECUTE',
        1056 : 'PAGE_WRITECOMBINE | PAGE_EXECUTE_READ',
        1088 : 'PAGE_WRITECOMBINE | PAGE_EXECUTE_READWRITE',
        1152 : 'PAGE_WRITECOMBINE | PAGE_EXECUTE_WRITECOPY',
}

MEMORY_ANALYSIS_DEPENDENCIES = {
        "diff_callbacks" : ["callbacks"],
        "diff_heap_entropy" : ["psxview"],
        "diff_hidden_processes" : ["psxview"],
        "diff_processes" : ["pslist"],
        "diff_modified_pe_header": ["modified_pe_header"],
        "diff_services" : ["svcscan"],
        "diff_devices" : ["devicetree"],
        "diff_kernel_modules" : ["modscan"],
        "diff_moddump" : ["moddump"],
        "diff_timers" : ["timers"],
        "diff_sockets" : ["sockets", "sockscan"],
        "diff_connections" : ["connscan", "connections"],
        "diff_malfind" : ["malfind"],
        "diff_autostart_reg_keys" : ["handles"],
        "diff_idt" : ["idt"],
        "diff_strings" : ["strings"],
        "diff_avstrings" : ["avstrings"],
        "diff_suspicious_windows_processes" : ["find_suspicious_windows_processes"],
        #"static_analyze_new_exe" : ["psxview"],
        "diff_mutantscan" : ["mutantscan"],
        "diff_messagehooks" : ["messagehooks"],
        "diff_eventhooks" : ["eventhooks"],
        "diff_dlllist" : ["dlllist"],
        "diff_ldrmodules" : ["ldrmodules"],
        "diff_threads" : ["threads"],
        "diff_handles" : ["handles"],
        "diff_file_handles" : ["file_handles"],
        "diff_hivelist" : ["hivelist"],
}
MEMORY_ANALYSIS_FUNCTIONS = {
        "diff_hidden_processes" : "get_new_hidden_processes",
        "diff_processes" : "get_new_processes",
        "diff_autostart_reg_keys" : "get_autostart_reg_keys",
        "diff_devices" : "get_new_devices",
        "diff_services" : "get_new_services",
        "diff_connections" : "get_new_connections",
        "diff_timers" : "get_new_timers",
        "diff_malfind" : "get_new_malfind",
        #"static_analyze_new_exe" : "static_analyze_new_exe",
        #"diff_static_analysis" : "diff_static_analysis",
        "diff_dlllist" : 'get_new_dlllist',
        "diff_mutantscan" : 'get_new_mutants',
        "diff_moddump" : "get_new_moddump",
}

TRIGGER_PLUGINS = {
        "ZwLoadDriver" : ["diff_moddump"],
        "__process__" : ["diff_processes"],
        "NtCreateMutant": ["diff_mutantscan"],
        "socket" : ["diff_sockets", "diff_connections"],
        "WriteProcessMemory" : ["diff_malfind"],
        "SetWinEventHook" : ["diff_eventhooks"],
        "SetWindowsHookExA" : ["diff_messagehooks"],
        "SetWindowsHookExW" : ["diff_messagehooks"],
	"NtCreateFile" : ["diff_file_handles"]
}

