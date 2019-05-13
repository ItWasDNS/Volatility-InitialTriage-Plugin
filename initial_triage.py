"""
Name: Matthew Sprengel
Assignment: Final Project
Description: Initial Triage Volatility Plugin
Professor: Jones
Class: CFRS 772
Tested: Python 3.7 on macOS
Code Citations:
 - The Art of Memory Forensics
 - Volatility Framework

Execute (Remove before submission):
 vol.py --plugins=/Users/Matthew-Sprengel/Git/Volatility-Initial-Triage-Plugin/
        -f ../../Memory_Samples/S1/sample001.bin initialtriage
"""

import time
import volatility.utils as utils
import volatility.win32 as win32
import volatility.timefmt as timefmt
import volatility.plugins.common as common
import volatility.plugins.imageinfo as imageinfo
import volatility.plugins.registry.registryapi as registry_api


class InitialTriage(common.AbstractWindowsCommand):
    """ Initial Triage Volatility Plugin """

    def most_recent_services(self):
        """ Return the Most Recently Started Services """
        # From 'The Art of Memory Forensics'
        regapi = registry_api.RegistryApi(self._config)
        key = "ControlSet001\Services"
        subkeys = regapi.reg_get_all_subkeys("system", key)
        services = dict((s.Name, int(s.LastWriteTime)) for s in subkeys)
        times = sorted(set(services.values()), reverse=True)
        top_three = times[0:3]
        recent_services = list()
        for time in top_three:
            for name, ts in services.items():
                if ts == time:
                    recent_services.append([time, name])
        return recent_services

    def calculate(self):
        """ Perform the Work """
        addr_space = utils.load_as(self._config)
        # Image Info
        print ""
        # Process List
        print "Memory Capture Summary"
        print "#====================#"
        # List Profiles and Select Best One
        # Retrieve OS information from registry
        # Code Goes Here
        iinfo = imageinfo.ImageInfo(self._config)
        image_time = iinfo.get_image_time(addr_space)
        print "Memory Captured: %s" % \
              timefmt.display_datetime(image_time['ImageDatetime'].as_datetime(),
                                       image_time['ImageTz'])
        print ""
        # Process List
        print "Process List"
        print "#==========#"
        proclist_pslist = win32.tasks.pslist(addr_space)
        for item in proclist_pslist:
            print(item)
        # Replace with pstree
        # Add potential malicious entries with psxview output
        # Diff with psxview and pstree?
        print ""
        # Services
        print "Recently Created Services"
        print "#=======================#"
        recent_services = self.most_recent_services()
        for item in recent_services:
            print time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(item[0])), \
                  item[1]
        # Network Connections
        # Code Goes Here
        # Differences in XP Listed
        # if Vista+ then netscan else connections/connscan and sockets/sockscan
        return {}

    def render_text(self, outfd, data):
        """ Output Results in Text """
        # Once Above is Completed:
        # Migrate output to json => Use json to render text
        print("output")

    def render_json(self, outfd, data):
        """ Output Results in Text """
        # Print json from above
        print("output")
