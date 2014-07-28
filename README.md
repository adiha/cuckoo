Cuckoo Sanbox fork for Memory Analysis.

<h3>
<a name="user-content-authors" class="anchor" href="#dependencies" aria-hidden="true"><span class="octicon octicon-link"></span></a>Dependencies</h3>
<ul class="task-list">
<li>Cuckoo's dependencies.</li>
<li>For static analysis of memory, download IDA free 5.0 and then replace its exe with our patched exe (in cuckoo/IDA/idag_patched.exe)</li>
<li>If yoy want to use our heap entropy calculator plugin, copy heap_entropy.py from Volatility directory (under master dir) to the Volatility plugins directory.</li>
<li>In order to use the monitorCPU trigger, you will have to run CPU.exe on your analysis machine.</li>
<li>In order to enable taking dumps and resuming execution, a few changes had to be made in cuckoomon.dll. The cuckoomon version that is supplied in this fork is not the one that was released with cuckoo 1.0. Make sure you use the version supplied by us.</li>
<li>It is recommended to use QEMU virtualization to enable VMI introspection. In order to do so, you should install your Cuckoo on Ubuntu and install the following software: Qemu 1.7.0, libvirt 1.0 and libvmi. To enable live introspection and patching the memory dump with Volatility, you will have to add the qemu addrspace plugin (if you are using Volatility 2.4, it comes with the default installation and no need in adding anything). The plugin can be found under our Volatility directory and should be placed in volatility/plugins/addrspaces/qemuelf.py.</li>
</ul>

<h3>
<a name="user-content-authors" class="anchor" href="#dependencies" aria-hidden="true"><span class="octicon octicon-link"></span></a>Usage</h3>
<ul class="task-list">
<li>Download zip and extract (ready for immidiate usage, no overriding files needed)</li>
<li>Configure cuckoo</li>
<li>Run cuckoo.py</li>
</ul>

<h3>
<a name="user-content-authors" class="anchor" href="#dependencies" aria-hidden="true"><span class="octicon octicon-link"></span></a>Configuring Cuckoo to run memory analysis</h3>
<ul class="task-list">
<li>In processing.conf, change the file to the following:
<pre><code>[memoryanalysis]
enabled = yes
</code></pre>
</li>
<li>Configure your memory analysis. You can find a new file, memoryanalysis.conf, in which you can set all the parameters for your analysis. This file includes a basic section:
<pre><code>[basic]
trigger_based = on
time_based = off
</code></pre>
Whether to enable trigger based or time based. Make sure you enable at least one of them.

In the time-based section, you can configure the number of seconds to sleep between two dumps:
<pre><code>[time_based]
time_to_sleep_before_dump_in_seconds = 30
</code></pre>
In the memory diff plugins section, you can choose to enable or disable the analysis plugins.
In case they are enabled, they will appear under every dump in the JSON report and will tell you which artifacts were added and which were deleted.
<pre><code>[diff_hidden_processes]
enabled = yes
desc = Detects new hidden processes
</code></pre>
Under the trigger points section, you can configure each trigger:
<pre><code>[Trigger_VirtualProtectEx]
# Enable / Disable
enabled = yes
# Whether to dump memory on this trigger
dump_memory = yes
# Whether to pause execution to enable live VMI inspection
break_on_volshell = no
# Which plugins to run when this trigger happens
run_plugins = diff_processes
# Whether to run automatic plugins on the trigger, based on its type.
run_smart_plugins = yes
# Whether to pause execution and open a python shell. 
# This enables to set more breakpoints dynamically.
breakpoint = off
# Max number of times for this trigger.
times = 1
</code></pre>
</li>
<li>If you want to use the regular Volatility plugins without doing any diff logic, just configure it in memory.conf, and the results will appear under every dump (the new report format is described in the following section).
Note: We also wrapped Existing Volatility plugins which were not wrapped by Cuckoo, they can also be used.</li>

</ul>
<h3>
<a name="user-content-authors" class="anchor" href="#dependencies" aria-hidden="true"><span class="octicon octicon-link"></span></a>Changes in the report</h3>
Cuckoo generates a JSON report (the data in it is used to generate the HTML report that can be viewed with the Cuckoo web server).
We made a few changes in this JSON report to include the memory analysis results, too.
Before adding our code, the report.json format was:
<pre><code>
{
	'memory' : {
			'malfind' : {} ...
		   }
}
</code></pre>
Now, we created a key in the result dictionary for each dump. The value of the key is the result dictionary for this dump.
The heirarchy looks like that:
<pre><code>
{
	'dumps' : {
		'Dump_1' : {
				'path' : '...'
				'meta' : {
						'trigger' : {...},
						'time' : "..."
					 }
		
			   } ,
		'Dump_2' : {...}
	}
}
</code></pre>

<h3>
<a name="user-content-authors" class="anchor" href="#dependencies" aria-hidden="true"><span class="octicon octicon-link"></span></a>Added Plugins</h3>
We added plugins which did not exist in Volatility.
<ul class="task-list">
<li>Heap entropy: Calculates the current heap entropy of a process.</li>
<li>AVStrings: Finds Anti-Virus strings in the dump.</li>
<li>Modified PE Header: Finds incomplete PE headers.</li>
</ul>
