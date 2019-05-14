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

import sys
import json
import time
import volatility.obj as obj
import volatility.utils as utils
import volatility.win32 as win32
import volatility.protos as protos
import volatility.timefmt as timefmt
import volatility.win32.tasks as tasks
# Plugins Imports
import volatility.plugins.common as common
import volatility.plugins.imageinfo as imageinfo
import volatility.plugins.netscan as netscan
import volatility.plugins.connscan as connscan
import volatility.plugins.sockscan as sockscan
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
        output = {}
        addr_space = utils.load_as(self._config)
        profile = 'DefXP'

        # Image Info
        iinfo = imageinfo.ImageInfo(self._config)
        image_time_raw = iinfo.get_image_time(addr_space)
        image_time = timefmt.display_datetime(image_time_raw['ImageDatetime'].as_datetime(),
                                 image_time_raw['ImageTz'])
        output['image_time'] = image_time

        # Process List
        proclist_pslist = win32.tasks.pslist(addr_space)
        for item in proclist_pslist:
            print int(item.UniqueProcessId), item.ImageFileName, item

        # Services
        recent_services = []
        for item in self.most_recent_services():
            svc = [time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(item[0])), str(item[1])]
            recent_services.append(svc)
        output['recent_services'] = recent_services

        # Network Connections
        if 'XP' in profile or '2003' in profile:
            # Process Sockets (XP / 2003)
            sockscan_c = sockscan.SockScan(self._config)
            sockscan_data = sockscan_c.calculate()
            sockets = []
            for sock in sockscan_data:
                sockets.append([int(sock.obj_offset),
                                int(sock.Pid),
                                int(sock.LocalPort),
                                int(sock.Protocol),
                                protos.protos.get(sock.Protocol.v(), "-"),
                                str(sock.LocalIpAddress),
                                sock.CreateTime
                                ])
            output['sockets'] = sockets
            # Process Connections (XP / 2003)
            connscan_c = connscan.ConnScan(self._config)
            connscan_data = connscan_c.calculate()
            connections = []
            for conn in connscan_data:
                connections.append([int(conn.obj_offset),
                                    str(conn.LocalIpAddress),
                                    int(conn.LocalPort),
                                    str(conn.RemoteIpAddress),
                                    int(conn.RemotePort),
                                    int(conn.Pid)
                                    ])
            output["connections"] = connections
        else:
            # Process Sockets/Connections (Vista+)
            netscan_c = netscan.Netscan(self._config)
            netscan_data = netscan_c.calculate()

        # Return output in JSON
        print output
        return str(output)

    def render_text(self, outfd, data):
        """ Output Results in Text """
        # Once Above is Completed:
        # Migrate output to json => Use json to render text
        print(data)
        output = json.loads(data)
        print ""
        # Process Image Summary
        print "Memory Capture Summary"
        print "#====================#"
        # Print Image Summary
        print "Memory Captured: %s" % output['image_time']
        print ""

        # Print Processes
        print "Process List"
        print "#==========#"

        print ""

        # Print Services
        print "Recently Created Services"
        print "#=======================#"
        for svc in output['recent_services']:
            print svc
        print ""

    def render_json(self, outfd, data):
        """ Output Results in JSON """
        print(data)

        # Replace with pstree
        # Add potential malicious entries with psxvixew output
        # Diff with psxview and pstree?
        # profilelist = [p.__name__ for p in
        #                registry.get_plugin_classes(obj.Profile).values()]
        # bestguess = None
        # suglist = [s for s, _ in kdbgscan.KDBGScan.calculate(kdbgscan.KDBGScan)]
        # if suglist:
        #     bestguess = suglist[0]
        # suggestion = ", ".join(set(suglist))
        # print bestguess
        # profile.metadata.get('os', 'unknown') == 'windows' and profile.metadata.get('major', 0) == 5
