Cuckoo Sanbox fork for Memory Analysis.

<h3>
<a name="user-content-authors" class="anchor" href="#dependencies" aria-hidden="true"><span class="octicon octicon-link"></span></a>Dependencies</h3>
<ul class="task-list">
<li>Cuckoo's dependencies.</li>
<li>For static analysis of memory, download IDA free 5.0 and then replace its exe with our patched exe (in cuckoo/IDA/idag_patched.exe)</li>
</ul>

<h3>
<a name="user-content-authors" class="anchor" href="#dependencies" aria-hidden="true"><span class="octicon octicon-link"></span></a>Usage</h3>
<ul class="task-list">
<li>Download zip</li>
<li>Configure cuckoo</li>
<li>Run cuckoo.py</li>
</ul>

<h3>
<a name="user-content-authors" class="anchor" href="#dependencies" aria-hidden="true"><span class="octicon octicon-link"></span></a>Configuring Cuckoo to run memory analysis</h3>
<ul class="task-list">
<li>In processing.conf, change the file to the following:
[memoryanalysis]
enabled = yes
</li>
<li>Configure your memory analysis. You can find a new file, memoryanalysis.conf, in which you can set all the parameters for your analysis.</li>
<li>If you want to use the regular Volatility plugins without doing any diff logic, just configure it in memory.conf, and the results will appear under every dump (the new report format is described in the following section).</li>
</ul>
<h3>
<a name="user-content-authors" class="anchor" href="#dependencies" aria-hidden="true"><span class="octicon octicon-link"></span></a>Changes in the report</h3>
Cuckoo generates a JSON report (the data in it is used to generate the HTML report that can be viewed with the Cuckoo web server).
We made a few changes in this JSON report to include the memory analysis results, too.
Before adding our code, the report.json format was:
{
	'memory' : {
			'malfind' : {} ...
		   }
}
Now, we created a key in the result dictionary for each dump. The value of the key is the result dictionary for this dump.
The heirarchy looks like that:

{
	'dumps' : {
		'Dump_1' : {
				'path' : '...'
				'meta' : {
						'trigger' : {...},
						'time' : "..."
					 }
		
			   },
		'Dump_2' : {...}
	}
}

