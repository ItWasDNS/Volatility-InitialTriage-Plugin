"""
    Name: Matthew Sprengel
    Assignment: Final Project
    Description: Initial Triage Volatility Plugin
    Professor: Jones
    Class: CFRS 772
    Tested on Python 3.7 on macOS
    Execute: vol.py --plugins=/Users/Matthew-Sprengel/Git/Vol_Plugin/
                    -f ../../Memory_Samples/S1/sample001.bin initialtriage
"""

import volatility.utils as utils
import volatility.win32 as win32
import volatility.plugins.common as common
import volatility.plugins.imageinfo as imageinfo
import volatility.plugins.registry.registryapi as registry_api


class InitialTriage(common.AbstractWindowsCommand):
    """Initial Triage Volatility Plugin"""

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
                    print(time, name)
                    recent_services.append((time, name))
        return recent_services

    def calculate(self):
        """ Perform the Work """
        addr_space = utils.load_as(self._config)
        # Image Info
        iinfo = imageinfo.ImageInfo(self._config)
        image_time = iinfo.get_image_time(addr_space)
        print(image_time)
        # Process List
        proclist_pslist = win32.tasks.pslist(addr_space)
        for item in proclist_pslist:
            print(item)
        # Services
        recent_services = self.most_recent_services()
        for item in recent_services:
            print(item[0], item[1])
        return {}

    def render_text(self, outfd, data):
        """ Output Results in Text """
        print("output")

    def render_json(self, outfd, data):
        """ Output Results in Text """
        print("output")
