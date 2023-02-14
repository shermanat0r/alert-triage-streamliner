 #!/usr/env/python3.10

"""
Name: Entities.py
Author: Caleb Bryant
Date: 2023/02/11
Description: Entity classes representing common details present in security incidents. Some entities have their own functions to enrich their information. 
"""

import os
from APIwrapper import APIwrapper

class Entity:
    def __init__(self, name, value):
        self.name = name
        self.value = value
        self.enrichments = None

class IP_Address(Entity):
    def __init__(self, value, ip_type):
        Entity.__init__(self, "IP Address", value)
        self.VT_url = "https://www.virustotal.com/api/v3/ip_addresses/{}".format(self.value)
        self.ip_type = ip_type

    def defang(self):
        return self.value.replace(".", "[.]", 1)

    def enrich(self):
        if not self.public:
            self.enrichments = "Internal IP address"
        else:
            wrapper = APIwrapper()
            self.enrichments = wrapper.VT_lookup(self).json()
            # leaving this in so I remember where the interesting data is in the JSON, thinking I want to move this somewhere else
            # harmless = self.enrichments["data"]["attributes"]["last_analysis_stats"]["malicious"]
            # malicious = self.enrichments["data"]["attributes"]["last_analysis_stats"]["suspicious"]
            # badVotes = harmless + malicious

class FileHash(Entity):
    def __init__(self, value):
        Entity.__init__(self, "File Hash", value, hash_type)
        self.VT_url = "https://www.virustotal.com/api/v3/files/{}".format(self.value)
        self.hash_type = hash_type

    def enrich(self):
        wrapper = APIwrapper()
        self.enrichments = wrapper.VT_lookup(self).json()

class Domain(Entity):
    def __init__(self, value):
        Entity.__init__(self, "Domain", value)
        self.VT_url = "https://www.virustotal.com/api/v3/domains/{}".format(self.value)
    
    def defang(self):
        defanged = self.value.replace(".", "[.]", 1)
        return defanged

    def enrich(self):
        wrapper = APIwrapper()
        self.enrichments = wrapper.VT_lookup(self).json()

class URL(Entity):
    def __init__(self, value):
        Entity.__init__(self, "URL", value)
        self.VT_url = "https://www.virustotal.com/api/v3/domains/{}".format(self.value)

    def enrich(self):
        wrapper = APIwrapper()
        self.enrichments = wrapper.VT_lookup(self).json()

    def defang(self):
        defanged = self.value.replace(".", "[.]", 1)
        protocol = defanged[:4]
        defanged = defanged.replace("http", "hxxp", 1)
        return defanged