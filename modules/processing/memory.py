# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import copy
import re
import tempfile
import itertools
import shutil
import json

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from modules.processing.static import PortableExecutable
import modules.processing.virustotal as vt

import memoryanalysis
import memoryanalysisconsts

try:
    import volatility.conf as conf
    import volatility.registry as registry
    import volatility.commands as commands
    import volatility.utils as utils
    import volatility.plugins.malware.devicetree as devicetree
    import volatility.plugins.malware.impscan as impscan
    import volatility.plugins.getsids as sidm
    import volatility.plugins.privileges as privm
    import volatility.plugins.taskmods as taskmods
    import volatility.win32.tasks as tasks
    import volatility.obj as obj
    import volatility.protos as protos
    import volatility.plugins.malware.malfind as malfind
    HAVE_VOLATILITY = True
except ImportError:
    HAVE_VOLATILITY = False

log = logging.getLogger(__name__)

class VolatilityAPI(object):
    """ Volatility API interface."""

    def __init__(self, memdump, osprofile=None, is_clean=False):
        """@param memdump: the memdump file path
        @param osprofile: the profile (OS type)
        """
        registry.PluginImporter()
        self.memdump = memdump
        self.osprofile = osprofile
        self.config = None
	self.is_clean = is_clean
	self.results = {}
        self.__config()

    def __config(self):
        """Creates a volatility configuration."""
        self.config = conf.ConfObject()
        self.config.optparser.set_conflict_handler("resolve")
        registry.register_global_options(self.config, commands.Command)
        base_conf = {
            "profile": "WinXPSP3x86",
            "use_old_as": None,
            "kdbg": None,
            "help": False,
            "kpcr": None,
            "tz": None,
            "pid": None,
            "output_file": None,
            "physical_offset": None,
            "conf_file": None,
            "dtb": None,
            "output": None,
            "info": None,
            "location": "file://" + self.memdump,
            "plugins": None,
            "debug": None,
            "cache_dtb": True,
            "filename": None,
            "cache_directory": None,
            "verbose": None,
            "write": False
        }

        if self.osprofile:
            base_conf["profile"] = self.osprofile

        for key, value in base_conf.items():
            self.config.update(key, value)

        self.addr_space = utils.load_as(self.config)
        self.plugins = registry.get_plugin_classes(commands.Command,
                                                   lower=True)
	
        return self.config


    # ADI
    def strings(self):
	"""
	Returns a list of strings found in the memory dump.
	"""
	strs = os.popen("strings -a -o %s" % self.memdump).read().split("\n")
	strings_dict = {}
	results = []
	for st in strs:
		if re.match("\d+ \S+", st) is not None:
			new = {
				"string" : st.strip().split(" ")[1]
		      		}
			results.append(memoryanalysis.hashabledict(new))
	return dict(config={}, 
		    data=list(set(results)))

    # ADI
    def find_strings(self, strs, lst):
	"""
	Returns a list of found strings from a prepared list
	"""
	suspicious_found_strings = []
	found_strs = [s.lower() for s in strs]
	if strs is None:
		strs = self.strings()
	for suspicious_string in lst:
		template = ".*%s.*" % suspicious_string.lower() 
		for s in found_strs:
			if re.match(template, s) is not None and not s in suspicious_found_strings:
				suspicious_found_strings.append(s)
	return dict(config={}, data=[{"string" : s} for s in suspicious_found_strings]
)

    # ADI
    def avstrings(self):
	if self.results.has_key("strings"):
		res = self.results["strings"]
	else:
		res = self.strings()
	return dict(config={}, 
                    data=self.find_strings([d['string'] for d in res['data']], memoryanalysisconsts.AV_NAMES + memoryanalysisconsts.AV_PROCESS_NAMES)['data'])
    # ADI
    def find_strings_from_list(self, lst):
	if self.results.has_key("strings"):
		res = self.results["strings"]
	else:
		res = self.strings()

	return dict(config={}, 
		    data=self.find_strings([d['string'] for d in res['data']], lst)['data'])

    # ADI
    def patcher(self, xml_path):
        """Volatility patcher plugin.
        """
        log.debug("Executing Volatility patcher plugin on "
                  "{0}".format(self.memdump))

        self.__config()
	self.config.WRITE = True
 	self.config.XML_INPUT = xml_path
        command = self.plugins["patcher"](self.config)
	scanner, addr_space = command.calculate()
	resfile = tempfile.mktemp()
	patches = scanner.scan(addr_space, file(resfile, 'wb'))
	res = file(resfile,"rb").read()
	os.remove(resfile)
	return dict(config={}, patches=patches, data=[res])

    # ADI: Added parent process name
    def pslist(self):
        """Volatility pslist plugin.
        @see volatility/plugins/taskmods.py
        """
        log.debug("Executing Volatility pslist plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []
	
        command = taskmods.PSList(self.config)
	calc1, calc2 = itertools.tee(command.calculate())
	
	# create pid:process_name mapping
	names = {}
	for process in calc1:
		names[int(process.UniqueProcessId)] = str(process.ImageFileName)

        for process in calc2:
	    if names.has_key(int(process.InheritedFromUniqueProcessId)):
		parent_name = names[int(process.InheritedFromUniqueProcessId)]
	    else:
		parent_name = "-"
            new = {
                "process_name": str(process.ImageFileName),
                "process_id": int(process.UniqueProcessId),
                "parent_id": int(process.InheritedFromUniqueProcessId),
                "parent_name": str(parent_name),
                "num_threads": str(process.ActiveThreads),
                "num_handles": str(process.ObjectTable.HandleCount),
                "session_id": str(process.SessionId),
                "create_time": str(process.CreateTime or ""),
                "exit_time": str(process.ExitTime or ""),
		"cmdline": str(process.Peb.ProcessParameters.CommandLine)
            }
	    if new['process_name'] != 'python.exe':
	            results.append(new)
	return dict(config={}, 
		    data=results)
    # ADI
    def threads(self, filter=None, pid=None):
        """Volatility threads plugin.
        @see volatility/plugins/taskmods.py
        """
        log.debug("Executing Volatility threads plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []
	self.config.PID = pid
	self.config.FILTER = filter
        command = self.plugins["threads"](self.config)
	for thread, addr_space, mods, mod_addrs, \
                     instances, hooked_tables, system_range, owner_name in command.calculate():
		tags = set([t for t, v in instances.items() if v.check()])
		new = {"TID" : int(thread.Cid.UniqueThread),
			"PID" : int(thread.Cid.UniqueProcess),
			"ETHREAD" : hex(int(thread.obj_offset)),
			"Owning Process" : str(thread.owning_process().ImageFileName),
			"Tags" : ','.join(tags),
			"State" : str(thread.Tcb.State),

			}
		results.append(new)
        #results = command.render_text(file('/dev/nul', 'wb'), command.calculate())
        return dict(config={}, 
		    data=results)

    # ADI
    def heapentropy(self, pid=None):
        """Volatility heapentropy plugin.
        @see volatility/plugins/heap_entropy.py
        """
        log.debug("Executing Volatility heapentropy plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []
	if pid is not None:
		self.config.PID = pid
        command = self.plugins["heapentropy"](self.config)
	entropies = []
	for proc, entropy in command.calculate():
		new = {
			"process_id" : proc,		
			"entropy" : entropy
		      }
		entropies.append(new)
	return dict(config={"PID": pid}, data=entropies)


    # ADI
    def impscan(self, pid=None):
        """Volatility impscan plugin.
        @see volatility/plugins/malware/impscan.py
        """
        log.debug("Executing Volatility impscan plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []
	if pid == None:
		log.debug("No PID for impscan, returning empty dict.")
		return dict(config={}, data=[])
	self.config.PID = pid
        command = self.plugins["impscan"](self.config)
	
        for iat, call, module, function in command.calculate():
            new = {
                "IAT": hex(int(iat)),
                "call": hex(int(call)),
                "module": str(module),
                "function": str(function),
            }
	    results.append(new)
	return dict(config={"PID": pid}, data=results)

    # ADI
    def impscan_all_processes(self):
	results = []
	if self.results.has_key("psxview"):
		procs = self.results["psxview"]["data"]
	else:
		procs = self.psxview()["data"]
	for p in procs:
		try:
			pid = p["process_id"]
			new = {"pid" : pid, 
				"imported_functions" : self.impscan(pid=pid)
			      }
			results.append(new)
		except:
			pass
	return dict(config={}, data=results)

    # ADI
    def malsysproc(self):
        """Volatility malsysproc plugin.
        @see volatility/plugins/malsysproc.py
        """
        log.debug("Executing Volatility malsysproc plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["malsysproc"](self.config)
        for info in command.calculate():
            new = {
		   'offset' : hex(int(info['offset'])),
		   'processname': str(info['processname']),
                   'pid' : int(info['pid']),
	           'name' : str(info['name']),
	           'path' : str(info['path']),
		   'ppid' : str(info['ppid']),
	           'time' : str(info['time']),
		   'priority' : str(info['priority']),
		   'cmdline' : str(info['cmdline']),
	           'count' : str(info['count'])		
            }

            results.append(new)
	return dict(config={}, 
		    data=results)

    # ADI
    def find_suspicious_windows_processes(self):
	"""
	Find suspicious processes according to their PIDs, cmdlines, priority, etc.
	"""
	if self.results.has_key("malsysproc"):
		malsysproc = self.results["malsysproc"]["data"]
	else:	
		malsysproc = self.malsysproc()["data"]
	
	sus = []

	for p in malsysproc:
		if p['name']     == "False" or \
  		   p['path']     == "False" or \
		   p['ppid']     == "False" or \
	 	   p['time']     == "False" or \
		   p['priority'] == "False" or \
		   p['cmdline']  == "False" or \
		   p['count']    == "False":
			sus.append(p)
	return dict(config={}, 
		    data=sus)

    def psxview(self):
        """Volatility psxview plugin.
        @see volatility/plugins/malware/psxview.py
        """
        log.debug("Executing Volatility psxview plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["psxview"](self.config)
        for offset, process, ps_sources in command.calculate():
            new = {
                "process_name": str(process.ImageFileName),
                "process_id": int(process.UniqueProcessId),
		"cmdline": str(process.Peb.ProcessParameters.CommandLine),
                "pslist": str(ps_sources['pslist'].has_key(offset)),
                "psscan": str(ps_sources['psscan'].has_key(offset)),
                "thrdproc": str(ps_sources['thrdproc'].has_key(offset)),
                "pspcid": str(ps_sources['pspcid'].has_key(offset)),
                "csrss": str(ps_sources['csrss'].has_key(offset)),
                "session": str(ps_sources['session'].has_key(offset)),
                "deskthrd": str(ps_sources['deskthrd'].has_key(offset))
            }

            results.append(new)
	return dict(config={}, 
		    data=results)

    def callbacks(self):
        """Volatility callbacks plugin.
        @see volatility/plugins/malware/callbacks.py
        """
        log.debug("Executing Volatility callbacks plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["callbacks"](self.config)
        for (sym, cb, detail), mods, mod_addrs in command.calculate():
            module = tasks.find_module(mods, mod_addrs, command.kern_space.address_mask(cb))

            if module:
                module_name = module.BaseDllName or module.FullDllName
            else:
                module_name = "UNKNOWN"

            new = {
                "type": str(sym),
                "callback": hex(int(cb)),
                "module": str(module_name),
                "details": str(detail or "-"),
            }

            results.append(new)
	return dict(config={}, 
		    data=results)

     # ADI
    def yarascan(self, rule_file, is_kernel=True):
        """Volatility yarascan plugin.
        """
        log.debug("Executing Volatility yarascan plugin on "
                  "{0}".format(self.memdump))
	results = []
	if rule_file is not None and os.path.exists(rule_file):

        	self.__config()
	
		self.config.YARA_FILE = rule_file
		if is_kernel:
			self.config.KERNEL = True
        	command = self.plugins["yarascan"](self.config)
		for o, address, hit, data in command.calculate():
			owner = ""
			if o is None:
				owner = "Owner: Unknown Kernel Memory"
			elif o.obj_name == "_EPROCESS":
                		owner = "Owner: Process {0} Pid {1}".format(o.ImageFileName, o.UniqueProcessId)
            		else:
                		owner = "Owner: {0}".format(o.BaseDllName)
				
			new = {"owner" : owner,
			       "address" : hex(int(address)),
			       "hit_rule" : str(hit),
			       "data" : str(data.encode("hex"))
			      }

			results.append(new)
	else:
		log.warning("Could not find rule file for YARA")	
	return dict(config={}, 
		    data=results)

    # ADI
    def procexedump(self, dump_dir=None, pid=None):
        """Volatility procexedump plugin.
        """
        log.debug("Executing Volatility procexedump plugin on "
                  "{0}".format(self.memdump))
        results = []

        self.__config()

       	if dump_dir:
		try:
			self.config.DUMP_DIR = dump_dir
			os.mkdir(dump_dir)
		except OSError:
			pass
        if pid:
		self.config.PID = pid
	command = self.plugins["procexedump"](self.config)
	data, data2 = itertools.tee(command.calculate())
        for t in data:
		
                new = {"offset" : hex(int(t.obj_offset)),
                       "address" : hex(int(t.Peb.ImageBaseAddress)),
                       "filename" : str(t.ImageFileName),
		      }
                results.append(new)
	command.render_text(file(r"/dev/null","wb"), data2)	
        return dict(config={"dump_dir":dump_dir}, 
		    data=results)
    # ADI
    def moddump(self, dump_dir=None, base=None):
        """Volatility moddump plugin.
        """
        log.debug("Executing Volatility moddump plugin on "
                  "{0}".format(self.memdump))
        results = []

        self.__config()

       	if dump_dir:
		try:
			self.config.DUMP_DIR = dump_dir
			os.mkdir(dump_dir)
		except OSError:
			pass
	else:
		dump_dir = tempfile.mkdtemp()
		self.config.DUMP_DIR = dump_dir
	if base:
		self.config.BASE = base
	self.config.REGEX = None
        command = self.plugins["moddump"](self.config)
	data, data2 = itertools.tee(command.calculate())
	command.render_text(file(r"/dev/null","wb"), data)
        for addr_space, procs, mod_base, mod_name in data2:
		
                new = {"module_base" : mod_base,
                       "module_name" : str(mod_name),
		      }
                results.append(new)
        return dict(config={"dump_dir":dump_dir}, 
		    data=results)

    def static_analysis(self):
        """
	Static analyze dumped exes
	"""
	results = []
	is_temp_dir = False
	if not self.results.has_key("procexedump"):
		dump_dir = tempfile.mkdtemp()
		res = self.procexedump(dump_dir=dump_dir)
		is_temp_dir = True
	else:
		dump_dir = self.results["procexedump"]["config"]["dump_dir"]
	for f in os.listdir(dump_dir):
		full_path = os.path.join(dump_dir, f)
		pe = PortableExecutable(full_path).run()
		pe["executable"] = f
		results.append(pe)
	if is_temp_dir:
		shutil.rmtree(dump_dir)
	return dict(config={}, 
		    data=results)

    def vt_analysis(self):
        """
	vt analyze dumped exes
	"""
	results = []
	is_temp_dir = False
	if not self.results.has_key("procexedump"):
		dump_dir = tempfile.mkdtemp()
		res = self.procexedump(dump_dir=dump_dir)
		is_temp_dir = True
	else:
		dump_dir = self.results["procexedump"]["config"]["dump_dir"]
	for f in os.listdir(dump_dir):
		full_path = os.path.join(dump_dir, f)
		results[f] = vt.run_vt_analysis_on_file(full_path)
	if is_temp_dir:
		shutil.rmtree(dump_dir)
	return dict(config={}, 
		    data=results)


    # ADI
    def dlldump(self, dump_dir=None, pid=None, base=None, regex=None):
        """Volatility dlldump plugin.
        """
        log.debug("Executing Volatility dlldump plugin on "
                  "{0}".format(self.memdump))
        results = []

        self.__config()

       	if dump_dir:
		try:
			self.config.DUMP_DIR = dump_dir
			os.mkdir(dump_dir)
		except OSError:
			pass
	if pid:
		self.config.PID = pid
	if regex:
		self.config.REGEX = regex
	if base:
		self.config.BASE = base
        command = self.plugins["dlldump"](self.config)
	data, data2 = itertools.tee(command.calculate())
        for proc, ps_ad, mod_base, mod_name in data:
		
                new = {"offset" : hex(int(proc.obj_offset)),
                       "module_base" : hex(int(mod_base)),
                       "filename" : str(proc.ImageFileName),
			"module_name": str(mod_name or ""),
		      }
                results.append(new)
	result = command.render_text(file(r"/dev/null","wb"), data2)
        return dict(config={}, 
		    result=result, 
		    data=results)

    # ADI
    def modified_pe_header(self):
	"""
	Searches for modified PE header using yara signature.
	"""
	rule =  'rule modified_pe_header {strings: $msg = "This program cannot" condition: ((not uint16(0) == 0x5A4D) and $msg)}'
	temp_rule_file = tempfile.mktemp()
	file(temp_rule_file,"wb").write(rule)
	res = self.yarascan(temp_rule_file)["data"]
	res2 = self.yarascan(temp_rule_file, is_kernel=True)["data"]
	os.remove(temp_rule_file)
	res += res2
	return dict(config={}, 
		    data=res)

    # ADI    
    def connscan(self):
        """Volatility connscan plugin.
        """
        log.debug("Executing Volatility connscan plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []
        command = self.plugins["connscan"](self.config)
	for tcp_object in command.calculate():
	
            new = {
                "offset": hex(int(tcp_object.obj_offset)),
                "local_address": str(tcp_object.LocalIpAddress),
		"local_port": int(tcp_object.LocalPort),
                "remote_address": str(tcp_object.RemoteIpAddress),
		"remote_port": int(tcp_object.RemotePort),
                "pid": int(tcp_object.Pid),
            }

            results.append(new)
	
	return dict(config={}, 
		    data=results)
    
    # ADI
    def connections(self):
        """Volatility connections plugin.
        """
        log.debug("Executing Volatility connections plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []
        command = self.plugins["connections"](self.config)
	for tcp_object in command.calculate():
	
            new = {
                "offset": hex(int(tcp_object.obj_offset)),
                "local_address": str(tcp_object.LocalIpAddress),
		"local_port": int(tcp_object.LocalPort),
                "remote_address": str(tcp_object.RemoteIpAddress),
		"remote_port": int(tcp_object.RemotePort),
                "pid": int(tcp_object.Pid),
            }

            results.append(new)
	
	return dict(config={}, 
		    data=results)

    # ADI
    def sockscan(self):
        """Volatility sockscan plugin.
        """
        log.debug("Executing Volatility sockscan plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []
        command = self.plugins["sockscan"](self.config)
	for sock_obj in command.calculate():
		new = {
                	"offset": hex(int(sock_obj.obj_offset)),
                	"local_address": str(sock_obj.LocalIpAddress),
			"local_port": int(sock_obj.LocalPort),
                	"create_time": str(sock_obj.CreateTime),
			"protocol": int(sock_obj.Protocol),
                	"pid": int(sock_obj.Pid),
			"proto": protos.protos.get(sock_obj.Protocol.v(), "-")
           	 }
		results.append(new)

	return dict(config={}, 
		    data=results)

    # ADI
    def sockets(self):
        """Volatility sockets plugin.
        """
        log.debug("Executing Volatility sockets plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []
        command = self.plugins["sockets"](self.config)
	for sock_obj in command.calculate():
		new = {
                	"offset": hex(int(sock_obj.obj_offset)),
                	"local_address": str(sock_obj.LocalIpAddress),
			"local_port": int(sock_obj.LocalPort),
                	"create_time": str(sock_obj.CreateTime),
			"protocol": int(sock_obj.Protocol),
                	"pid": int(sock_obj.Pid),
			"proto": protos.protos.get(sock_obj.Protocol.v(), "-")
           	 }
		results.append(new)

	return dict(config={}, 
		    data=results)
    # ADI
    def hivelist(self):
        """Volatility hivelist plugin.
        """
        log.debug("Executing Volatility hivelist plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []
        command = self.plugins["hivelist"](self.config)
        hive_offsets = []
	for hive in command.calculate():
		try:
                    name = str(hive.FileFullPath or '') or str(hive.FileUserName or '') or str(hive.HiveRootPath or '') or "[no name]"
                except AttributeError:
                    name = "[no name]"
                # Spec of 10 rather than 8 width, since the # puts 0x at the start, which is included in the width
                hive_offsets.append(hive.obj_offset)
            	new = {
                	"physical_address": hex(int(hive.obj_offset)),
                	"virtual_address": hex(int(hive.obj_vm.vtop(hive.obj_offset))),
                	"name": str(name),
            		}

            	results.append(new)

        return dict(config={}, 
		    data=results)

    def idt(self):
        """Volatility idt plugin.
        @see volatility/plugins/malware/idt.py
        """
        log.debug("Executing Volatility idt plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["idt"](self.config)
        for n, entry, addr, module in command.calculate():
            if module:
                module_name = str(module.BaseDllName or '')
                sect_name = command.get_section_name(module, addr)
            else:
                module_name = "UNKNOWN"
                sect_name = ''

            # The parent is IDT. The grand-parent is _KPCR. 
            cpu_number = entry.obj_parent.obj_parent.ProcessorBlock.Number
            new = {
                "cpu_number": int(cpu_number),
                "index": hex(int(n)),
                "selector": hex(int(entry.Selector)),
                "address": hex(int(addr)),
                "module": module_name,
                "section": sect_name,
            }
            results.append(new)

        return dict(config={}, 
		    data=results)

    def timers(self):
        """Volatility timers plugin.
        @see volatility/plugins/malware/timers.py
        """
        log.debug("Executing Volatility timers plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["timers"](self.config)
        for timer, module in command.calculate():
            if timer.Header.SignalState.v():
                signaled = "Yes"
            else:
                signaled = "-"

            if module:
                module_name = str(module.BaseDllName or '')
            else:
                module_name = "UNKNOWN"

            due_time = "{0:#010x}:{1:#010x}".format(timer.DueTime.HighPart, timer.DueTime.LowPart)

            new = {
                "offset": hex(timer.obj_offset),
                "due_time": due_time,
                "period": int(timer.Period),
                "signaled": signaled,
                "routine": hex(int(timer.Dpc.DeferredRoutine)),
                "module": module_name,
            }
            results.append(new)

        return dict(config={}, 
		    data=results)

    # ADI
    def eventhooks(self):
	log.debug("Executing Volatility eventhooks plugin on "
                  "{0}".format(self.memdump))
	results = []
	self.__config()
	command = self.plugins["eventhooks"](self.config)
    	for session in command.calculate():
		shared_info = session.find_shared_info()

            	if not shared_info:
                	continue

            	filters = [lambda x : str(x.bType) == "TYPE_WINEVENTHOOK"]
	    	new = {}
    	    	for handle in shared_info.handles(filters):
			new["type"] = str(handle.bType)
			new["flags"] = int(handle.bFlags)
			new["thread"] = int(handle.Thread.Cid.UniqueThread)
			new["process"] = int(handle.Process.UniqueProcessId)
            		
                	event_hook = handle.reference_object()
			new["eventMin"] = str(event_hook.eventMin.v())
			new["eventMax"] = str(event_hook.eventMax.v())
			new["event_hook_flags"] = str(event_hook.dwFlags)
			new["offPfn"] = int(event_hook.offPfn)
			new["idProcess"] = int(event_hook.idProcess)
			new["idThread"] = int(event_hook.idThread)
			#new["ihmod"] = event_hook.ihmod
			results.append(new)
	return dict(config={}, 
		    data=results)

    def messagehooks(self):
        """Volatility messagehooks plugin.
        @see volatility/plugins/malware/messagehooks.py
        """
        log.debug("Executing Volatility messagehooks plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["messagehooks"](self.config)
        for winsta, atom_tables in command.calculate():
            for desk in winsta.desktops():
                for name, hook in desk.hooks():
                    module = command.translate_hmod(winsta, atom_tables, hook.ihmod)
                    new = {
                        "offset": hex(int(hook.obj_offset)),
                        "session": int(winsta.dwSessionId),
                        "desktop": "{0}\\{1}".format(winsta.Name, desk.Name),
                        "thread": "<any>",
                        "filter": str(name),
                        "flags": str(hook.flags),
                        "function": hex(int(hook.offPfn)),
                        "module": str(module),
                    }
                    results.append(new)

                for thrd in desk.threads():
                    info = "{0} ({1} {2})".format(
                        thrd.pEThread.Cid.UniqueThread,
                        thrd.ppi.Process.ImageFileName,
                        thrd.ppi.Process.UniqueProcessId)

                    for name, hook in thrd.hooks():
                        module = command.translate_hmod(winsta, atom_tables, hook.ihmod)

                        new = {
                            "offset": hex(int(hook.obj_offset)),
                            "session": int(winsta.dwSessionId),
                            "desktop": "{0}\\{1}".format(winsta.Name, desk.Name),
                            "thread": str(info),
                            "filter": str(name),
                            "flags": str(hook.flags),
                            "function": hex(int(hook.offPfn)),
                            "module": str(module),
                        }
                        results.append(new)

        return dict(config={}, 
		    data=results)

    def getsids(self):
        """Volatility getsids plugin.
        @see volatility/plugins/malware/getsids.py
        """

        log.debug("Executing Volatility getsids plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["getsids"](self.config)
        for task in command.calculate():
            token = task.get_token()

            if not token:
                continue

            for sid_string in token.get_sids():
                if sid_string in sidm.well_known_sids:
                    sid_name = " {0}".format(sidm.well_known_sids[sid_string])
                else:
                    sid_name_re = sidm.find_sid_re(sid_string, sidm.well_known_sid_re)
                    if sid_name_re:
                        sid_name = " {0}".format(sid_name_re)
                    else:
                        sid_name = ""

                new = {
                    "filename": str(task.ImageFileName),
                    "process_id": int(task.UniqueProcessId),
                    "sid_string": str(sid_string),
                    "sid_name": str(sid_name),
                }
                results.append(new)

        return dict(config={}, 
		    data=results)

    def privs(self):
        """Volatility privs plugin.
        @see volatility/plugins/malware/privs.py
        """

        log.debug("Executing Volatility privs plugin on "
                  "{0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["privs"](self.config)

        for task in command.calculate():
            for value, present, enabled, default in task.get_token().privileges():
                try:
                    name, desc = privm.PRIVILEGE_INFO[int(value)]
                except KeyError:
                    continue 

                attributes = []
                if present:
                    attributes.append("Present")
                if enabled:
                    attributes.append("Enabled")
                if default:
                    attributes.append("Default")

                new = {
                    "process_id": int(task.UniqueProcessId),
                    "filename": str(task.ImageFileName),
                    "value": int(value),
                    "privilege": str(name),
                    "attributes": ",".join(attributes),
                    "description": str(desc),
                }
                results.append(new)

        return dict(config={}, data=results)
    # ADI
    def get_vad_data(self, vad, address_space):
    	offset = vad.Start
    	out_of_range = vad.Start + vad.Length
    	while offset < out_of_range:
    		to_read = min(1024 * 1024 * 10, out_of_range - offset)
        	data = address_space.zread(offset, to_read)
        	if not data:
        		break
        	offset += to_read
    	return data

    # AD
    def vadwalk(self):
        """Volatility vadwalk plugin.
        """
        log.debug("Executing Volatility vadwalk plugin on "
                  "{0}".format(self.memdump))

        self.__config()
	if pid is not None:
		conf = copy.deepcopy(self.config)
		conf.PID = pid
	else:
		conf = self.config
        results = []
        command = self.plugins["vadwalk"](conf)
        for task in command.calculate():
		for vad in task.VadRoot.traverse():
                # Ignore Vads with bad tags (which we explicitly include as None)
                	if vad:
                    		new = {
                        	"address" : vad.obj_offset,
                        	"parent": vad.Parent.obj_offset or 0,
                        	"left" : vad.LeftChild.dereference().obj_offset or 0,
                        	"right" : vad.RightChild.dereference().obj_offset or 0,
                        	"start" : vad.Start,
                        	"end" : vad.End,
                        	"tag" : vad.Tag }

		   
                    		results.append(new)
        return dict(config={},
		    data=results)



    # ADI: added dump_dir and pid
    def malfind(self, dump_dir=None, pid=None, add_data=False, ignore_protect=False, address=None):
        """Volatility malfind plugin.
        @param dump_dir: optional directory for dumps
        @see volatility/plugins/malware/malfind.py
        """
        log.debug("Executing Volatility malfind plugin on "
                  "{0}".format(self.memdump))

        self.__config()
	if pid is not None:
		conf = copy.deepcopy(self.config)
		conf.PID = pid
	else:
		conf = self.config
        results = []
        # Create a subdir under the output dir
        if dump_dir and not self.is_clean:
            #malfind_dir = os.path.join(dump_dir, "malfind")
            try:
		os.mkdir(dump_dir)
	    except:
		pass
        command = self.plugins["malfind"](conf)
	
        for task in command.calculate():
	    if ignore_protect:
		vad_filter = task._injection_filter_noprotect
	    else:
		vad_filter = task._injection_filter
	    
            for vad, address_space in task.get_vads(vad_filter=vad_filter):
                if command._is_vad_empty(vad, address_space):
                    continue
		
                new = {
                    "process_name": str(task.ImageFileName),
                    "process_id": int(task.UniqueProcessId),
                    "vad_start": "{0:#x}".format(vad.Start),
                    "vad_tag": str(vad.Tag),
		    "offset" : int(task.obj_offset)
                }

                if dump_dir and not self.is_clean:
		    filename = os.path.join(dump_dir, "process.{0:#x}.{1:#x}.dmp".format(task.obj_offset, vad.Start))
                    if (address is not None and address == vad.Start) or address is None:
			command.dump_vad(filename, vad, address_space)
		if add_data:
			new['data'] = self.get_vad_data(vad, address_space)
		if address == None or address == vad.Start:   
                	results.append(new)
        return dict(config={'dump_dir' : dump_dir},
		    data=results)

    # ADI: added pid option
    def apihooks(self, pid=None):
        """Volatility apihooks plugin.
        @see volatility/plugins/malware/apihooks.py
        """
        log.debug("Executing Volatility apihooks plugin on {0}".format(self.memdump))

        self.__config()
        results = []
	if pid is not None:
		conf = copy.deepcopy(self.config)
		conf.PID = pid
	else:
		conf = self.config
        command = self.plugins["apihooks"](conf)
        for process, module, hook in command.calculate():
            new = {
                "hook_mode": str(hook.Mode),
                "hook_type": str(hook.Type),
                "victim_module": str(module.BaseDllName or ""),
                "victim_function": str(hook.Detail),
                "hook_address": "{0:#x}".format(hook.hook_address),
                "hooking_module": str(hook.HookModule)
            }

            if process:
                new["process_id"] = int(process.UniqueProcessId)
                new["process_name"] = str(process.ImageFileName)

            results.append(new)

        return dict(config={}, 
		    data=results)

    def dlllist(self):
        """Volatility dlllist plugin.
        @see volatility/plugins/taskmods.py
        """
        log.debug("Executing Volatility dlllist plugin on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["dlllist"](self.config)
        for task in command.calculate():
            new = {
                "process_id": int(task.UniqueProcessId),
                "process_name": str(task.ImageFileName),
                "commandline": str(task.Peb.ProcessParameters.CommandLine or ""),
                "loaded_modules": []
            }

            for module in task.get_load_modules():
                new["loaded_modules"].append({
                    "dll_base": str(module.DllBase),
                    "dll_size": str(module.SizeOfImage),
                    "dll_full_name": str(module.FullDllName or ""),
                    "dll_load_count": int(module.LoadCount),
                })

            results.append(new)

        return dict(config={}, 
		    data=results)

    def handles(self):
        """Volatility handles plugin.
        @see volatility/plugins/handles.py
        """
        log.debug("Executing Volatility handles plugin on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["handles"](self.config)
        for pid, handle, object_type, name in command.calculate():
            new = {
                "process_id": int(pid),
                "handle_value": str(handle.HandleValue),
                "handle_granted_access": str(handle.GrantedAccess),
                "handle_type": str(object_type),
                "handle_name": str(name)
            }

            results.append(new)

        return dict(config={}, 
		    data=results)

    def file_handles(self):
        """Volatility handles plugin on files.
        @see volatility/plugins/handles.py
        """
        log.debug("Executing Volatility handles plugin on {0}".format(self.memdump))

        self.__config()
        results = []
	self.config.OBJECT_TYPE = "File"
        command = self.plugins["handles"](self.config)
        for pid, handle, object_type, name in command.calculate():
            new = {
                "process_id": int(pid),
                "handle_value": str(handle.HandleValue),
                "handle_granted_access": str(handle.GrantedAccess),
                "handle_type": str(object_type),
                "handle_name": str(name)
            }
	    if new["handle_type"] == "File":
	            results.append(new)

        return dict(config={}, 
		    data=results)

    def ldrmodules(self):
        """Volatility ldrmodules plugin.
        @see volatility/plugins/malware/malfind.py
        """
        log.debug("Executing Volatility ldrmodules plugin on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["ldrmodules"](self.config)
        for task in command.calculate():
            # Build a dictionary for all three PEB lists where the
            # keys are base address and module objects are the values.
            inloadorder = dict((mod.DllBase.v(), mod) for mod in task.get_load_modules())
            ininitorder = dict((mod.DllBase.v(), mod) for mod in task.get_init_modules())
            inmemorder = dict((mod.DllBase.v(), mod) for mod in task.get_mem_modules())

            # Build a similar dictionary for the mapped files.
            mapped_files = {}
            for vad, address_space in task.get_vads(vad_filter=task._mapped_file_filter):
                # Note this is a lot faster than acquiring the full
                # vad region and then checking the first two bytes.
                if obj.Object("_IMAGE_DOS_HEADER", offset=vad.Start, vm=address_space).e_magic != 0x5A4D:
                    continue

                mapped_files[int(vad.Start)] = str(vad.FileObject.FileName or "")

            # For each base address with a mapped file, print info on
            # the other PEB lists to spot discrepancies.
            for base in mapped_files.keys():
                # Does the base address exist in the PEB DLL lists?
                load_mod = inloadorder.get(base, None)
                init_mod = ininitorder.get(base, None)
                mem_mod = inmemorder.get(base, None)

                new = {
                    "process_id": int(task.UniqueProcessId),
                    "process_name": str(task.ImageFileName),
                    "dll_base": "{0:#x}".format(base),
                    "dll_in_load": not load_mod is None,
                    "dll_in_init": not init_mod is None,
                    "dll_in_mem": not mem_mod is None,
                    "dll_mapped_path": str(mapped_files[base]),
                    "load_full_dll_name": "",
                    "init_full_dll_name": "",
                    "mem_full_dll_name": ""
                }

                if load_mod:
                    new["load_full_dll_name"] = str(load_mod.FullDllName)

                if init_mod:
                    new["init_full_dll_name"] = str(init_mod.FullDllName)

                if mem_mod:
                    new["mem_full_dll_name"] = str(mem_mod.FullDllName)

                results.append(new)

        return dict(config={}, 
		    data=results)

    def mutantscan(self):
        """Volatility mutantscan plugin.
        @see volatility/plugins/filescan.py
        """
        log.debug("Executing Volatility mutantscan module on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["mutantscan"](self.config)
        for object_obj, mutant in command.calculate():
            tid = 0
            pid = 0
            if mutant.OwnerThread > 0x80000000:
                thread = mutant.OwnerThread.dereference_as("_ETHREAD")
                tid = thread.Cid.UniqueThread
                pid = thread.Cid.UniqueProcess

            new = {
                "mutant_offset": "{0:#x}".format(mutant.obj_offset),
                "num_pointer": int(object_obj.PointerCount),
                "num_handles": int(object_obj.HandleCount),
                "mutant_signal_state": str(mutant.Header.SignalState),
                "mutant_name": str(object_obj.NameInfo.Name or ""),
                "process_id": int(pid),
                "thread_id": int(tid)
            }

            results.append(new)

        return dict(config={}, 
		    data=results)

    def devicetree(self):
        """Volatility devicetree plugin.
        @see volatility/plugins/malware/devicetree.py
        """
        log.debug("Executing Volatility devicetree module on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["devicetree"](self.config)
        for _object_obj, driver_obj, _ in command.calculate():
            new = {
                "driver_offset": "0x{0:08x}".format(driver_obj.obj_offset),
                "driver_name": str(driver_obj.DriverName or ""),
                "devices": []
            }

            for device in driver_obj.devices():
                device_header = obj.Object(
                    "_OBJECT_HEADER",
                    offset=device.obj_offset - device.obj_vm.profile.get_obj_offset("_OBJECT_HEADER", "Body"),
                    vm=device.obj_vm,
                    native_vm=device.obj_native_vm
                )

                device_name = str(device_header.NameInfo.Name or "")

                new_device = {
                    "device_offset": "0x{0:08x}".format(device.obj_offset),
                    "device_name": device_name,
                    "device_type": devicetree.DEVICE_CODES.get(device.DeviceType.v(), "UNKNOWN"),
                    "devices_attached": []
                }

                new["devices"].append(new_device)

                level = 0

                for att_device in device.attached_devices():
                    device_header = obj.Object(
                        "_OBJECT_HEADER",
                        offset=att_device.obj_offset - att_device.obj_vm.profile.get_obj_offset("_OBJECT_HEADER", "Body"),
                        vm=att_device.obj_vm,
                        native_vm=att_device.obj_native_vm
                    )

                    device_name = str(device_header.NameInfo.Name or "")
                    name = (device_name + " - " + str(att_device.DriverObject.DriverName or ""))

                    new_device["devices_attached"].append({
                        "level": level,
                        "attached_device_offset": "0x{0:08x}".format(att_device.obj_offset),
                        "attached_device_name": name,
                        "attached_device_type": devicetree.DEVICE_CODES.get(att_device.DeviceType.v(), "UNKNOWN")
                    })

                    level += 1

            results.append(new)

        return dict(config={},
	   	    data=results)

    def svcscan(self):
        """Volatility svcscan plugin - scans for services.
        @see volatility/plugins/malware/svcscan.py
        """
        log.debug("Executing Volatility svcscan plugin on {0}".format(self.memdump))
        
        self.__config()
        results = []
        
        command = self.plugins["svcscan"](self.config)
        for rec in command.calculate():
            new = {
                "service_offset": "{0:#x}".format(rec.obj_offset),
                "service_order": int(rec.Order),
                "process_id": int(rec.Pid),
                "service_name": str(rec.ServiceName.dereference()),
                "service_display_name": str(rec.DisplayName.dereference()),
                "service_type": str(rec.Type),
                "service_binary_path": str(rec.Binary),
                "service_state": str(rec.State)
            }

            results.append(new)

        return dict(config={}, 
		    data=results)

    def modscan(self):
        """Volatility modscan plugin.
        @see volatility/plugins/modscan.py
        """
        log.debug("Executing Volatility modscan plugin on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["modscan"](self.config)
        for ldr_entry in command.calculate():
            new = {
                "kernel_module_offset": "{0:#x}".format(ldr_entry.obj_offset),
                "kernel_module_name": str(ldr_entry.BaseDllName or ""),
                "kernel_module_file": str(ldr_entry.FullDllName or ""),
                "kernel_module_base": "{0:#x}".format(ldr_entry.DllBase),
                "kernel_module_size": int(ldr_entry.SizeOfImage),
            }

            results.append(new)

        return dict(config={}, 
		    data=results)

    def imageinfo(self):
        """Volatility imageinfo plugin.
        @see volatility/plugins/imageinfo.py
        """
        log.debug("Executing Volatility imageinfo plugin on {0}".format(self.memdump))

        self.__config()
        results = []

        command = self.plugins["imageinfo"](self.config)
        new = {}
        for key, value in command.calculate():
            new[key] = value

        osp = new["Suggested Profile(s)"].split(",")[0]
        new["osprofile"] = osp

        results.append(new)

        return dict(config={}, 
		    data=results)


class VolatilityManager(object):
    """Handle several volatility results."""
    def __init__(self, memfile, file_path=None, osprofile=None, clean_data=None, clean_dump=None, clean=False, output_dir=None, machine=None):
        self.mask_pid = []
        self.taint_pid = set()
        self.memfile = memfile
	self.output_dir = output_dir
	# ADI: If we don't have clean data, we are running on the clean dump!
	self.is_clean = clean_data is None
	self.clean_data = clean_data
	self.clean_dump = clean_dump
        self.file_path = file_path
	self.machine = machine
	if clean_dump is None:
		self.clean_dump = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s_clean.dmp" % self.machine)
	else:
		self.clean_dump = clean_dump
	conf_path = os.path.join(CUCKOO_ROOT, "conf", "memory.conf")
        if not os.path.exists(conf_path):
            log.error("Configuration file volatility.conf not found".format(conf_path))
            self.voptions = False
            return

        self.voptions = Config(conf_path)

        for pid in self.voptions.mask.pid_generic.split(","):
            pid = pid.strip()
            if pid:
                self.mask_pid.append(int(pid))

        self.no_filter = not self.voptions.mask.enabled
        if self.voptions.basic.guest_profile:
            self.osprofile = self.voptions.basic.guest_profile
        else:
            self.osprofile = osprofile or self.get_osprofile()

    def get_osprofile(self):
        """Get the OS profile"""        
        return VolatilityAPI(self.memfile).imageinfo()["data"][0]["osprofile"] 

    def run(self):
        # Exit if options were not loaded.
        if not self.voptions:
            return
        self.vol = VolatilityAPI(self.memfile, self.osprofile, self.is_clean)

        # TODO: improve the load of volatility functions.
	if not self.is_clean:
		# ADI: We don't want to run if it's running on the clean dump for memory analysis purposes. 
		if self.voptions.pslist.enabled:
		    self.vol.results["pslist"] = self.vol.pslist()
		if self.voptions.psxview.enabled:
		    self.vol.results["psxview"] = self.vol.psxview()
		if self.voptions.callbacks.enabled:
		    self.vol.results["callbacks"] = self.vol.callbacks()
		if self.voptions.idt.enabled:
		    self.vol.results["idt"] = self.vol.idt()
		if self.voptions.timers.enabled:
		    self.vol.results["timers"] =  self.vol.timers()
		if self.voptions.messagehooks.enabled:
		    self.vol.results["messagehooks"] = self.vol.messagehooks()
		if self.voptions.eventhooks.enabled:
                    self.vol.results["eventhooks"] = self.vol.eventhooks()
		if self.voptions.getsids.enabled:
		    self.vol.results["getsids"] = elf.vol.getsids()
		if self.voptions.privs.enabled:
		    self.vol.results["privs"] = self.vol.privs()
		if self.voptions.malfind.enabled:
		    self.vol.results["malfind"] = self.vol.malfind(dump_dir=self.output_dir)
		if self.voptions.apihooks.enabled:
		    self.vol.results["apihooks"] = self.vol.apihooks()
		if self.voptions.dlllist.enabled:
		    self.vol.results["dlllist"] = self.vol.dlllist()
		if self.voptions.handles.enabled:
		    self.vol.results["handles"] = self.vol.handles()
		if self.voptions.ldrmodules.enabled:
		    self.vol.results["ldrmodules"] = self.vol.ldrmodules()
		if self.voptions.mutantscan.enabled:
		    self.vol.results["mutantscan"] = self.vol.mutantscan()
		if self.voptions.devicetree.enabled:
		    self.vol.results["devicetree"] = self.vol.devicetree()
		if self.voptions.svcscan.enabled:
		    self.vol.results["svcscan"] = self.vol.svcscan()
		if self.voptions.modscan.enabled:
		    self.vol.results["modscan"] = self.vol.modscan()
		if self.voptions.connections.enabled:
		    self.vol.results["connections"] = self.vol.connections()
		if self.voptions.connscan.enabled:
		    self.vol.results["connscan"] = self.vol.connscan()
		if self.voptions.sockscan.enabled:
		    self.vol.results["sockscan"] = self.vol.sockscan()
		if self.voptions.sockets.enabled:
		    self.vol.results["sockets"] = self.vol.sockets()
		if self.voptions.yarascan.enabled:
		    rule = self.voptions.yarascan.rule_file
		    self.vol.results["yarascan"] = self.vol.yarascan(rule)
		if self.voptions.strings.enabled:
		    self.vol.results["strings"] = self.vol.strings()
		if self.voptions.modified_pe_header.enabled:
		    self.vol.results["modified_pe_header"] = self.vol.modified_pe_header()
		if self.voptions.avstrings.enabled:
		    self.vol.results["avstrings"] = self.vol.avstrings()
		if self.voptions.malsysproc.enabled:
		    self.vol.results["malsysproc"] = self.vol.malsysproc()
		if self.voptions.find_suspicious_windows_processes.enabled:
		    self.vol.results["find_suspicious_windows_processes"] = self.vol.find_suspicious_windows_processes()
		
		if self.voptions.find_strings_from_list.enabled:
		    lst = eval(self.voptions.find_strings_from_list.lst)
		    self.vol.results["find_strings_from_list"] = self.vol.find_strings_from_list(lst)
        	if self.voptions.procexedump.enabled:
			dump_dir = self.voptions.procexedump.dump_dir
			self.vol.results["procexedump"] = self.vol.procexedump(dump_dir)
		if self.voptions.dlldump.enabled:
			dump_dir = self.voptions.dlldump.dump_dir
			self.vol.results["dlldump"] = self.vol.dlldump(dump_dir)
		if self.voptions.static_analysis.enabled:
			self.vol.results["static_analysis"] = self.vol.static_analysis()
		if self.voptions.vt_analysis.enabled:
			self.vol.results["vt_analysis"] = self.vol.vt_analysis()
		if self.voptions.moddump.enabled:
			dump_dir = self.voptions.moddump.dump_dir
			self.vol.results["moddump"] = self.vol.moddump()
		if self.voptions.hivelist.enabled:
			self.vol.results["hivelist"] = self.vol.hivelist()
		if self.voptions.impscan_all_processes.enabled:
			self.vol.results["impscan_all_processes"] = self.vol.impscan_all_processes()

	self.find_taint(self.vol.results)
        self.cleanup()
        self.vol.results = self.mask_filter(self.vol.results)
	
	# ADI: Added memory analysis module
	
	mem_analysis = {}
	new_results = {}
	if self.voptions.memoryanalysis.enabled:
		#mem_analysis = memoryanalysis.run_memory_analysis(self.voptions, vol, results, self.memfile.split('/')[-2], self.is_clean, self.clean_data)
	
	#	mem_analysis, new_results = memoryanalysis.run_memory_analysis(self.voptions, self.vol, self.results, self.memfile.split('/')[-2], self.is_clean, self.clean_data)
		mem_analysis, new_results = memoryanalysis.MemoryAnalysis(self.voptions, self.vol, self.memfile, self.file_path, self.is_clean, self.clean_data, self.clean_dump).run_memory_analysis()
		

	return mem_analysis, self.vol.results, new_results

    def mask_filter(self, old):
        """Filter out masked stuff. Keep tainted stuff."""
        new = {}

        for akey in old.keys():
            new[akey] = {"config": old[akey]["config"], "data": []}
            conf = getattr(self.voptions, akey, None)
            new[akey]["config"]["filter"] = conf.filter
            for item in old[akey]["data"]:
                # TODO: need to improve this logic.
                if not conf.filter:
                    new[akey]["data"].append(item)
                elif ("process_id" in item and item["process_id"] in self.mask_pid and not item["process_id"] in self.taint_pid):
                    pass
                else:
                    new[akey]["data"].append(item)
        return new

    def find_taint(self, res):
        """Find tainted items."""
        if "malfind" in res:
            for item in res["malfind"]["data"]:
                self.taint_pid.add(item["process_id"])

    def cleanup(self):
        """Delete the memory dump (if configured to do so)."""

        if self.voptions.basic.delete_memdump:
            try:
                os.remove(self.memfile)
            except OSError:
                log.error("Unable to delete memory dump file at path \"%s\" ", self.memfile)

class Memory(Processing):
    """Volatility Analyzer."""
    # ADI
    def get_machine_volatility_data(self, machine_name):
	"""
	Gets the clean data for the given machine
	"""
	# ADI
	from lib.cuckoo.core import scheduler
	import json
	for machine in scheduler.machinery.machines():
		if machine.name == machine_name:
			return json.loads(machine.clean_volatility)

    @staticmethod
    def should_compare_to_previous():
	"""
	Returns True if should compare to previous dump and not to clean,
	Else returns False.
	"""
        conf_path = os.path.join(CUCKOO_ROOT, "conf", "memoryanalysis.conf")
	voptions = Config(conf_path)
	return voptions.basic.compare_to_previous_dump

    def run(self):
        """Run analysis.
        @return: volatility results dict.
        """
	
        self.key = "dumps"
        results = {}
        if HAVE_VOLATILITY:
	    # ADI: Get previous volatility data if we already have it.
            vol_data = self.get_machine_volatility_data(self.task['machine'])
	    vol_dump = None
	    for mem_dir in sorted(os.listdir(self.memory_dumps_dir_path)):
		mem = os.path.join(self.memory_dumps_dir_path, mem_dir, "memory.dmp")
		if mem and os.path.exists(mem):
                	try:
		    	#output_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task["id"]), "memory")
                    		output_dir = os.path.dirname(mem)
		    		#vol = VolatilityManager(mem, clean_data=vol_data, output_dir=output_dir)
				vol = VolatilityManager(mem, file_path=self.file_path, clean_data=vol_data, clean_dump=vol_dump, output_dir=output_dir, machine=self.task['machine'])
			
                    		#results['Dump_%s' % mem_dir] = vol.run()
                    		mem_analysis, memo, new_results = vol.run()
				results["Dump_%s" % mem_dir] = {}
				info_json_file = os.path.join(output_dir, "info.json")
                		if os.path.exists(info_json_file):
                        		info = json.load(file(info_json_file, "rb"))

				results["Dump_%s" % mem_dir]["meta"] = info
				results["Dump_%s" % mem_dir]["memory"] = dict(mem_analysis.items() + memo.items())
				results["Dump_%s" % mem_dir]["path"] = mem
				if self.should_compare_to_previous():
					#vol_data = results['Dump_%s' % mem_dir][0]
					vol_data = new_results
					vol_dump = mem
                	except Exception:
                    		log.exception("Generic error executing volatility")
            	else:
                	log.error("Memory dump not found: to run volatility you have to enable memory_dump")
        else:
            log.error("Cannot run volatility module: volatility library not available")
	

	return results
