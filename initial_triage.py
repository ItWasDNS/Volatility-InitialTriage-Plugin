"""
Name: Matthew Sprengel
Assignment: Final Project
Description: InitialTriage Volatility Plugin
Professor: Jones
Class: CFRS 772
Tested: Python 2.7 on macOS
Code Citations:
 - The Art of Memory Forensics
 - Volatility Framework
"""

import sys
import time
import volatility.utils as utils
import volatility.protos as protos
import volatility.timefmt as timefmt
import volatility.plugins.common as common
import volatility.plugins.imageinfo as imageinfo
import volatility.plugins.pstree as pstree
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
        """ Perform the Initial Triage of the Memory Sample """
        # Initial Setup
        output = {}

        # Process the Image Info to include Time of Memory Capture (imageinfo)
        iinfo = imageinfo.ImageInfo(self._config)
        profile = self._config.PROFILE
        addr_space = utils.load_as(self._config)
        image_time_raw = iinfo.get_image_time(addr_space)
        image_time = timefmt.display_datetime(image_time_raw['ImageDatetime'].as_datetime(),
                                              image_time_raw['ImageTz'])
        output["image_time"] = image_time

        # Process the currently running Processes (pstree)
        pstree_data = pstree.PSTree(self._config).calculate()
        output["pstree"] = pstree_data

        # Process the most recently created Services (most_recent_services)
        recent_services = []
        for item in self.most_recent_services():
            svc = [time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(item[0])),
                   str(item[1])]
            recent_services.append(svc)
        output["recent_services"] = recent_services

        # Process the Connections and Sockets (connscan, sockscan)
        if 'XP' in profile or '2003' in profile:
            # Process Connections (Pre-Vista)
            connscan_c = connscan.ConnScan(self._config)
            connscan_data = connscan_c.calculate()
            connections = []
            for conn in connscan_data:
                connections.append([str(conn.obj_offset),
                                    str(conn.LocalIpAddress),
                                    int(conn.LocalPort),
                                    str(conn.RemoteIpAddress),
                                    int(conn.RemotePort),
                                    int(conn.Pid)
                                    ])
            output["connections"] = connections

            # Process Sockets (Pre-Vista)
            sockscan_c = sockscan.SockScan(self._config)
            sockscan_data = sockscan_c.calculate()
            sockets = []
            for sock in sockscan_data:
                sockets.append([str(sock.obj_offset),
                                int(sock.Pid),
                                str(sock.LocalIpAddress),
                                int(sock.LocalPort),
                                str(protos.protos.get(sock.Protocol.v(), "-")),
                                timefmt.display_datetime(sock.CreateTime.as_datetime())
                                ])
            output["sockets"] = sockets

        # Return output in JSON
        return output

    def render_text(self, outfd, data):
        """ Output Results in Text """
        print ""

        print " Memory Capture Summary "
        print "#======================#"
        print "Memory Captured: %s" % data['image_time']
        print ""

        print "Processes"
        print "#=======#"
        pstree.PSTree(self._config).render_text(sys.stdout, data["pstree"])
        print ""

        print "Recently Created Services"
        print "#=======================#"
        print("{:<21}{:<20}".format("Time Created", "Service"))
        print "-"*20, "-"*19
        for svc in data['recent_services']:
            print("{:<21}{:<20}".format(svc[0], svc[1]))
        print ""

        print "Connections"
        print "#=========#"
        if "connections" in data.keys():
            conn_format = "{:<12}{:<17}{:<12}{:<17}{:<13}{:<7}"
            print(conn_format.format("Offset",
                                     "Local IP",
                                     "Local Port",
                                     "Remote IP",
                                     "Remote Port",
                                     "PID"))
            print "-"*11, "-"*16, "-"*11, "-"*16, "-"*12, "-"*6
            for conn in data["connections"]:
                print conn_format.format(conn[0],
                                         conn[1],
                                         conn[2],
                                         conn[3],
                                         conn[4],
                                         conn[5])
        print ""

        print "Sockets"
        print "#=====#"
        if "sockets" in data.keys():
            sockets_format = "{:<12}{:<7}{:<17}{:<6}{:<11}{:<28}"
            print(sockets_format.format("Offset",
                                        "PID",
                                        "IP Address",
                                        "Port",
                                        "Protocol",
                                        "Creation Time"))
            print "-"*11, "-"*6, "-"*16, "-"*5, "-"*10, "-"*27
            for sock in data["sockets"]:
                print sockets_format.format(sock[0],
                                            sock[1],
                                            sock[2],
                                            sock[3],
                                            sock[4],
                                            sock[5])
        print ""

    def render_json(self, outfd, data):
        """ Output Results in JSON """
        print(data)
