# <u>InitialTriage Plugin for Volatility</u>

### Overview
The InitialTriage plugin for Volatility performs an initial set of triage on a 
memory sample by running a set of Volatility plugins and additional processing
to enable an investigator to look at the output of a single Volatility plugin
and determine if anything looks immediately suspicious or needs to be
investigated further.

The InitialTriage plugin also enables investigators to output multiple plugins
of interest in JSON which can then be ingested into other scripts and tools to
reduce the amount of effort required to pivot in their analysis. It is worth
noting that the initial version of the InitialTriage plugin works with systems
prior to Windows Vista and is not a one size fits all solution.

### Plugin Usage
To run the InitialTriage plugin, follow the steps below:
1) Download the initial_triage.py file
2) Change directory (`cd`) to the directory containing initial_triage.py
3) Run `cd` on Windows or `pwd` on Linux or macOS to determine the full path to
the directory which contains the InitialTriage Volatility plugin.
3) Change directory (`cd`) to the directory containing the Volatity source code
and vol.py.
4) Run the following command:
```
python vol.py --plugins={full_path_of_directory_containing initial_triage.py}
-f {full_path_of_memory_sample} --output={text|json} initialtriage 
```

### Testing
To test the plugin, you can run the imageinfo, pstree, sockscan, and connscan
plugins and compare the output to the output of the InitialTriage plugin. You
can also validate the most recent services using volshell similar to how it is
used in the book The Art of Memory Forensics. The provided memory samples were
used in the CFRS 710 Memory Forensics course at GMU.

### Future Work
Future work includes handling additional plugins, standardizing output, and 
additional enrichment of the standard Volatility plugins to provide greater
context to an investigator when looking at a memory sample for the first time.
