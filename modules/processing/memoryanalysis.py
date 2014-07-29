import copy
import os			
import re
import tempfile
import shutil
import pydeep
import time
import json
import logging

from lib.cuckoo.common.config import Config
import lib.cuckoo.common.utils as utils
from lib.cuckoo.common.constants import *
from modules.processing.static import PortableExecutable

import modules.processing.memory

from volatility.plugins import volshell
import volatility.plugins.vadinfo as vadinfo

import distorm3

log = logging.getLogger(__name__)


def disasm_from_memory(memory_dump_path, pid, base_address, memory_len):
	"""
	Returns disassembly of a region from the memory
	"""
	data = get_memory_from_proc(memory_dump_path, pid, base_address, memory_len)
	iterable = distorm3.DecodeGenerator(base_address, data, distorm3.Decode32Bits)
	ret = ""
        for (offset, _size, instruction, hexdump) in iterable:
                ret += "{0:<#8x} {1:<32} {2}".format(offset, hexdump, instruction)
	return ret

def get_memory_from_proc(memory_dump_path, pid, base_address, memory_len):
        """
        Gets a given length of memory from a dump file from a given PID.
        Returns None if the memory was unreadable.
        """
        # We use volatility API just in order to get it to set our config correctly
        m = modules.processing.memory.VolatilityAPI(memory_dump_path)
        v = volshell.volshell(m.config)
        v.addrspace = m.addr_space
        v.set_context(pid=pid)
        return v.proc.get_process_address_space().read(base_address, memory_len)


def add_static_to_malfind(res):
	"""
	Adds static information to malfind, if it is a PE
	"""
	res2 = []
        for i in res:
        	if i["data"].startswith("MZ".encode("hex")):
                	# Write file
                        data = i["data"].decode("hex")
                        temp_f = tempfile.mktemp()
                        file(temp_f,"wb").write(data)
                        i["static"] = PortableExecutable(temp_f).run()
                        os.remove(temp_f)
                res2.append(i)
        return res2

class hashabledict(dict):
    """
    Class that enables dictionary sets.
    """
    def __hash__(self):
        	return hash(tuple(sorted(self.items())))

class MemoryAnalysis(object):
	"""
	Class for Memory analysis diff logics.
	"""
	def __init__(self, vol, memfile, file_path, is_clean, clean_data, clean_dump):
		self.voptions = Config(os.path.join(CUCKOO_ROOT, "conf", "memoryanalysis.conf"))
		self.vol_manager = vol
		
		self.results = vol.results
		self.memfile = memfile
		self.file_path = file_path
		self.is_clean = is_clean
		self.clean_data = clean_data
		self.clean_dump = clean_dump
		if not self.is_clean:
			self.vol_manager = copy.deepcopy(vol)
		self.clean_dump = clean_dump
		dump_dir = os.path.dirname(self.memfile)
		self.info = None
		info_json_file = os.path.join(dump_dir, "info.json")
		if os.path.exists(info_json_file):
			self.info = json.load(file(info_json_file, "rb"))
		self.vol = modules.processing.memory.VolatilityAPI(self.memfile)
		self.clean_vol = None
		if os.path.exists(self.clean_dump):
			self.clean_vol = modules.processing.memory.VolatilityAPI(self.clean_dump)


	def run_dependencies(self, results, dependencies, **attrs):
		"""
		Runs each dependency if its result does not already exist  
		"""
		if attrs.has_key("desc"):
			attrs.pop("desc")
		for dep in dependencies:
			if not results.has_key(dep):
				results[dep] = getattr(self.vol_manager, dep)(**attrs)
		return results

	def get_new_objects(self, old, new, deps):
		"""
		Gets the diff between the old dump and new dump objects.
		"""
		hashable_united_old = set([])
		hashable_united_new = set([])
		for dep in deps:
			hashable_united_old = hashable_united_old | set([hashabledict(d) for d in old[dep]['data']])
			hashable_united_new = hashable_united_new | set([hashabledict(d) for d in new[dep]['data']])
		return list(set(hashable_united_new) - set(hashable_united_old))

	def get_new_dlllist(self, old, new, deps):
		"""
		Finds new loaded DLLs according to the owning process and DLL name.
		"""
		new_dlls = []
		for proc in new['dlllist']['data']:
			pid = proc['process_id']
			pname = proc['process_name']
			old_p = None
			for p in old['dlllist']['data']:
				if pid == p['process_id']:
					old_p = p
					break
			if old_p is not None:
				for module in proc['loaded_modules']:
					found = False
					for m in old_p['loaded_modules']:
						if m['dll_full_name'] == module['dll_full_name']:
							found = True
							break
					if not found:
						module['process_id'] = pid
						module['process_name'] = pname
						new_dlls.append(module)
		return new_dlls
	
	def get_new_by_field(self, old, new, deps, fields):
		"""
		Gets new objects according to specified fields to compare.
		"""
		found_objs = self.get_new_objects(old, new, deps)
		new_objs = []
		
		for o in found_objs:
			exist = False
			for o2 in old[deps[0]]['data']:
				similar = True
				for f in fields:
					if not o[f] == o2[f]:
						similar = False
						break
				if similar:
					exist = True
					break
			if not exist:
				new_objs.append(o)

		return new_objs

	def get_new_handles(self, old, new, deps):
		"""
		Gets new handles according to the owning process and handle value.
		"""
		return self.get_new_by_field(old,new,deps,['process_id', 'handle_value'])

	def get_new_timers(self, old, new, deps):
		"""
		Gets new timers according to their offset.
		"""
		return self.get_new_by_field(old, new, deps, ['offset'])

	def get_new_mutants(self, old, new, deps):
		"""
		Gets new mutants according to the mutant name.
		"""
		return self.get_new_by_field(old, new, deps, ['mutant_name'])

	def get_new_connections(self, old, new, deps):
		"""
		Gets new connections. 
		Filters out cuckoo's connections.
		"""
		found_connections = self.get_new_objects(old, new, deps)
		new_connections = []
		cuckoo_conf = Config(os.path.join(CUCKOO_ROOT, "conf", "cuckoo.conf"))
		remote_port = cuckoo_conf.resultserver.port
		remote_address = cuckoo_conf.resultserver.ip
		for c in found_connections:
			if not (c["local_port"] == CUCKOO_GUEST_PORT or \
			   c['remote_port'] == remote_port or \
			   c["remote_address"]	== remort_address):
				new_connections.append(c)
		return new_connections

	def get_new_malfind(self, old, new, deps, dump_dir=None):
		"""
		Gets new malfinds. Filters out malfunds in python processes.
		"""
		found_mals = self.get_new_objects(old, new, deps)
		new_mals = []
		malfinds_dir = os.path.join(os.path.dirname(self.memfile), "malfinds//")
		for m in found_mals:
			if not (m["process_name"] == "python.exe"):
				new_mals.append(m)
		# Copy new drivers to dir
		if dump_dir is not None:
                	for new_mal in new_mals:
				name = "process.{0:#x}.{1:#x}.dmp".format(new_mal["offset"], int(new_mal["vad_start"],16))
				utils.copy_safe(dump_dir + '//' + name, malfinds_dir + name)
                        	utils.remove_dir_safe(old["malfind"]["config"]["dump_dir"])
                        	utils.remove_dir_safe(new["malfind"]["config"]["dump_dir"])

		return new_mals

	def get_new_processes(self, old, new, deps):
		"""
		Gets new processes between old and new dumps accroding to PID.
		"""
		return self.get_new_by_field(old, new, deps, ['process_id'])

	def get_new_services(self, old, new, deps):
		"""
		Returns new services. Compares according to the service name.
		"""
		return self.get_new_by_field(old, new, deps, ['service_name'])

	def get_new_devices(self, old, new, deps):
		"""
		Gets new devices according to the device name and type.
		"""
		old_drivers = old[deps[0]]['data']
		new_drivers = new[deps[0]]['data']
		found_devs = []
		for new_driver in new_drivers:
			new_devices = new_driver["devices"]
			for new_device in new_devices:
				is_new = True
				for old_driver in old_drivers:
					old_devices = old_driver["devices"]
					for old_device in old_devices:
						if old_device["device_name"] == new_device["device_name"] and \
						   old_device["device_type"] == new_device["device_type"]:
							is_new = False
							break
					if not is_new:
						break
				if is_new:
					found_devs.append(new_device)
		return found_devs

	def get_new_hidden_processes(self, old, new, deps):
		"""
		Finds hidden processes.
		Uses psxview plugin of Volatility to compare between a few techniques to find processes.
		"""
		proclist = self.get_new_processes(old, new, deps)
		hidden = []
		for proc in proclist:
			for rule in PSXSCAN_RULES:
				should_add = True
				for (attr, val) in rule.iteritems():
					if proc[attr] != val:
						should_add = False
						break
				# Avoid adding cuckoo's hidden process
				if should_add and proc['process_name'] != "python.exe":
					hidden.append(proc)
					break
		return hidden		

	def get_new_moddump(self, old, new, deps):
		"""
		Dumps new drivers.
		"""
		moddir = os.path.join(os.path.dirname(self.memfile), "drivers//")
                res = self.get_new_objects(old, new, deps)

                # Copy new drivers to dir
                for new_driver in res:
			utils.copy_safe(new["moddump"]["config"]["dump_dir"] + \
			"/driver.{0:x}.sys".format(new_driver["module_base"]), moddir + new_driver["module_name"])
		utils.remove_dir_safe(old["moddump"]["config"]["dump_dir"])
		utils.remove_dir_safe(new["moddump"]["config"]["dump_dir"])
		return res

	def get_autostart_reg_keys(self, old, new, deps):
		"""
		Finds new autostart registry keys in the memory.
		"""
		autostart = []
		for new_handle in new[deps[0]]['data']:
			is_autostart = False
			if new_handle['handle_type'] == 'Key':
				for k in AUTOSTART_REG_KEYS:
					if k in new_handle["handle_value"].lower():
						is_autostart = True
						break
				if is_autostart:
					autostart.append(new_handle)
		return autostart

	def get_malware_proc(self, old, new, deps):
		"""
		Finds the malware's process in the system (if it is called m.exe).
		"""
		processes = new['psxview']['data']
                mal_exe_proc = None
                for new_proc in processes:
                        if "m.exe" in new_proc["process_name"]:
                                mal_exe_proc = new_proc
                                break
		return mal_exe_proc

	def get_injected_thread(self, pid, tid, mem_analysis, dis=None):
		"""
		Adds information about the injected thread.
		"""
		mem_analysis["diffs"]["injected_thread"] = {
								"new" 		: [],
								"deleted"	: [],
								"star"		: "yes", 
								"desc"		: "Shows the injected thread", 
								"disassembly" 	: dis
							   }
                threads = self.vol.threads(pid=pid)["data"]
                for t in threads:
                	if t["TID"] == tid:
                        	mem_analysis["diffs"]["injected_thread"]["new"].append(t)

	def static_analyze_new_exe(self, old, new, deps, return_data=False):
		"""
		Static analysis of the new exe.
		"""
		mal_exe_proc = self.get_malware_proc(old,new,deps)
		if mal_exe_proc is None:
			return []
		dump_dir = os.path.dirname(self.memfile)
		vol = modules.processing.memory.VolatilityAPI(self.memfile)
		vol.procexedump(dump_dir=dump_dir, pid=str(mal_exe_proc["process_id"]))
		if len(os.listdir(dump_dir)) > 1:
			new_exe = None
			for f in os.listdir(dump_dir):
				if f.endswith(".exe"):
					new_exe = f
					break
			if new_exe == None:
				return []
			new_exe_full_path = os.path.join(dump_dir,new_exe)
			static = PortableExecutable(new_exe_full_path).run()
			file_data = file(new_exe_full_path, "rb").read()
			static["pid"] = mal_exe_proc["process_id"]
			try:
				os.remove(r'/tmp/functions')
			except:
				pass
			command = r'wine "C:\Program Files (x86)\IDA Free\idag_patched.exe" \
				  -A -S"%s/IDA/script.idc" "%s" &' % (CUCKOO_ROOT, new_exe_full_path)
            		os.system(command)
            		time.sleep(30)
            		os.system("pkill idag_patched")
            		pefuncs = [a.split("^") for a in file(r'/tmp/functions','rb').read().split("--------------\r\n")]
			funcs = []
			try:
                		funcs.remove([""])
            		except:
                		pass

            		for func in pefuncs:
                		buf = ""
                		if len(func) == 3:
                        		for i in func[2]:
                                		try:
                                        		i.encode('utf-8')
                                        		buf += i
                                		except UnicodeDecodeError:
                                   	     		pass
                        		funcs.append({'name':func[0], 'data':func[1], 'disassembly':buf})
			static["pe_functions"] = funcs
			static["path"] = new_exe_full_path
			if not return_data:
				return [static]
			else:
				return [static], file_data
		return []

	def parse_trigger_plugins(self, trigger):
		"""
		Parses trigger entry in the memory analysis configuration.
		Returns whether to run smart analysis,
		and plugins to run for this trigger.
		"""
		smart_analysis = False
		plugins = []
		if hasattr(self.voptions, "Trigger_" + trigger):
			trig_opts = getattr(self.voptions, "Trigger_" + trigger)
			if trig_opts.run_smart_plugins:
				smart_analysis = True
			if trig_opts.run_plugins != "":
				plugins = trig_opts.run_plugins.split(",")
		return smart_analysis, plugins

	def run_memory_plugin(self, mem_analysis, memfunc, clean, new_results, **attrs):
		"""
		Checks that dependencies exist and then run the memory plugin.
		Finds new and deleted artifacts.
		New objects are found by detecting artifacts that exist in the new dump, but not in the old one.
		Old objects are found by detecting artifacts that exist in the old dump, but not in the new one.
		"""
		desc = getattr(self.voptions, memfunc).desc
		if attrs.has_key("desc"):
			attrs.pop("desc")
		deps = MEMORY_ANALYSIS_DEPENDENCIES[memfunc]
		for dep in deps:
			if not clean.has_key(dep):
				clean[dep] = getattr(self.clean_vol, dep)()
			if not new_results.has_key(dep):
				new_results[dep] = getattr(self.vol, dep)()

		if MEMORY_ANALYSIS_FUNCTIONS.has_key(memfunc):
                	analysis_func = getattr(self, MEMORY_ANALYSIS_FUNCTIONS[memfunc])
                else:
                        analysis_func = self.get_new_objects
		if not mem_analysis["diffs"].has_key(memfunc):
			log.info("Running plugin: %s" % memfunc)
                        mem_analysis["diffs"][memfunc] = {"desc" : desc}
			mem_analysis["diffs"][memfunc]["new"] = analysis_func(clean, new_results, deps, **attrs)
			mem_analysis["diffs"][memfunc]["deleted"] = analysis_func(new_results, clean, deps, **attrs)
			mem_analysis["diffs"][memfunc]["star"] = "no"

	def run_memory_analysis(self):		
		"""
		The main engine function for memory analysis
		"""
		# We copy the results because we add results that the user did not choose to run,
		# but will run as a dependency.
		log.info("Running memory analysis for dump: %s" % self.memfile)
		new_results = copy.deepcopy(self.results)
		mem_analysis = {}
		mem_analysis["diffs"] = {}
		dlls_dir = os.path.join(os.path.dirname(self.memfile), "dlls")
                drivers_dir = os.path.join(os.path.dirname(self.memfile), "drivers")
                malfinds_dir = os.path.join(os.path.dirname(self.memfile), "malfinds")

		if not self.is_clean:
                        utils.create_dir_safe(dlls_dir)
			utils.create_dir_safe(drivers_dir)
			utils.create_dir_safe(malfinds_dir)
		for mem_analysis_name, dependencies in MEMORY_ANALYSIS_DEPENDENCIES.iteritems():
			attrs = getattr(self.voptions, mem_analysis_name)
			if attrs.enabled:
				attrs.pop("enabled")
				desc = attrs["desc"]
				if attrs.has_key("filter"):
					attrs.pop("filter")
				if self.is_clean:
                                	self.results = self.run_dependencies(self.results, dependencies, **attrs)
                        	else:
                                	new_results = self.run_dependencies(new_results, dependencies, **attrs)
					if mem_analysis_name == "static_analyze_new_exe":
						mem_analysis[mem_analysis_name] = self.static_analyze_new_exe(self.clean_data, new_results, dependencies, **attrs)
					elif mem_analysis_name == "diff_heap_entropy":
						mem_analysis["diffs"]["diff_heap_entropy"] = {"desc" : "Calculates entropy of malware heap process", "new" : [], "deleted" : [], "star": "no"}
						proc = self.get_malware_proc(self.clean_data,new_results,dependencies)
                				if proc is not None:
                        				pid = proc["process_id"]
							try:
                        					mem_analysis["diffs"]["diff_heap_entropy"]["value"] = self.vol.heapentropy(pid=str(pid))["data"][0]["entropy"]
							except:
								pass
					else:
						self.run_memory_plugin(mem_analysis, mem_analysis_name, self.clean_data, new_results, **attrs)
		if not self.is_clean:
			trigger = self.info["trigger"]["name"]
			args = self.info["trigger"]["args"]
			smart_analysis, plugins_to_run = self.parse_trigger_plugins(trigger)
			for plugin in plugins_to_run:
				if not mem_analysis["diffs"].has_key(plugin):
                                	self.run_memory_plugin(mem_analysis, plugin, self.clean_data, new_results)
			if smart_analysis:
			    if TRIGGER_PLUGINS.has_key(trigger):
				for plugin in TRIGGER_PLUGINS[trigger]:
					if not mem_analysis["diffs"].has_key(plugin):
						self.run_memory_plugin(mem_analysis, plugin, self.clean_data, new_results)			
					mem_analysis["diffs"][plugin]["star"] = "yes"

			    if trigger == "monitorCPU":
				if mem_analysis["diffs"].has_key("diff_heap_entropy"):
					mem_analysis["diffs"]["diff_heap_entropy"]["star"] = "yes"
		    	    if trigger == "ZwLoadDriver":
				patcher_res = self.vol.patcher(os.path.join(CUCKOO_ROOT, "data", "patchers", "patchpe.xml"))
				# Dump the new driver

				for p in patcher_res["patches"]:
					log.info("Dumping drive in offset: %d" % p)
					base = int(p) + 0x7fe00000
					res = self.vol.moddump(dump_dir=drivers_dir, base=base)
					name = res["data"][0]["module_name"]
					mem_analysis["diffs"]["diff_moddump"]["new"].append({"module_name" : name,"module_base" : base})
			    elif trigger == "SetWindowsHookExA" or trigger == "SetWindowsHookExW":
			    	for mh in mem_analysis["diffs"]["diff_messagehooks"]["new"]:
						pid_pat = "\(.*?(\d+)\)"
						
						pids = re.findall(pid_pat, mh["thread"])
						if len(pids) > 0:
							pid = pids[0]
							mod_name = mh["module"].split("\\")[-1]
							dlldump = self.vol.dlldump(dump_dir=dlls_dir, pid=pid, regex=mod_name)
							mem_analysis["diffs"]["injected_dll"] = {
                        									"new"           : [],
                        									"deleted"       : [],
                        									"star"          : "yes",
                        									"desc"          : "Shows the injected DLL",
                        									}
							if dlldump["data"] != []:
								mem_analysis["diffs"]["injected_dll"]["new"].append(dlldump["data"][0])	
			    elif trigger == "VirtualProtectEx":
				verbal_protect = PAGE_PROTECTIONS[int(args["Protection"],16)]
				protect_vad_val = [key for key,val in vadinfo.PROTECT_FLAGS.iteritems() if val == verbal_protect][0]
        			if "EXECUTE" in verbal_protect:
					mem_analysis["diffs"]["diff_malfind"]["new"].append(self.vol.malfind(dump_dir=malfinds_dir, pid=str(args["ProcessId"]), add_data=False, ignore_protect=True, address=int(args["Address"],16))["data"][0])
				else:				
					mem_analysis["diffs"]["diff_malfind"]["deleted"].append(self.vol.malfind(dump_dir=None, pid=str(args["ProcessId"]), add_data=False, ignore_protect=True, address=int(args["Address"],16))["data"][0])
				mem_analysis["diffs"]["diff_malfind"]["star"] = "yes"
		    	    elif trigger == "WriteProcessMemory -> CreateRemoteThread -> LoadLibrary":
			 	resdir = os.path.join(os.path.dirname(self.memfile), "dlls")
                                utils.create_dir_safe(resdir)
				pid = str(args["ProcessId"])
				base = int(args["BaseAddress"], 16)
				
				new_dlldump = self.vol.dlldump(dump_dir=resdir, pid=pid, base=base)
				mem_analysis["diffs"]["injected_thread"] = \
					{
                        		"new"           : new_dlldump["data"],
                        		"deleted"       : [],
                        		"star"          : "yes",
                        		"desc"          : "Shows the injected thread",
                        		}
		    	    elif trigger == "NtSetContextThread -> NtResumeThread":
				pid = str(args["ProcessId"])
				tid = int(args["ThreadId"])
				self.get_injected_thread(pid, tid, mem_analysis)
		    	    elif trigger == "WriteProcessMemory -> CreateRemoteThread":
				start = int(args["StartRoutine"], 16)
				pid = str(args["ProcessId"])
                                tid = int(args["ThreadId"])
				dis = None
                                try:
                                        dis = disasm_from_memory(self.memfile, int(pid), start, 100)
                                except:
                                        pass
				self.get_injected_thread(pid, tid, mem_analysis, dis)

		return mem_analysis, new_results
