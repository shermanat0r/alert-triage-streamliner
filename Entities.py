 #!/usr/env/python3.10

"""
Name: Entities.py
Author: Caleb Bryant
Organization: Cyderes
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

class IPaddr(Entity):
    def __init__(self, value, ipType):
        Entity.__init__(self, "IP Address", value)
        self.VT_url = "https://www.virustotal.com/api/v3/ip_addresses/{}".format(self.value)
        self.type = ipType

    def defang(self):
        return self.value.replace(".", "[.]", 1)

    def enrich(self):
        wrapper = APIwrapper()
        self.enrichments = wrapper.VT_lookup(self).json()
        # leaving this in so I remember where the interesting data is, thinking I want to move this somewhere else
        # harmless = self.enrichments["data"]["attributes"]["last_analysis_stats"]["malicious"]
        # malicious = self.enrichments["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        # badVotes = harmless + malicious

class FileHash(Entity):
    def __init__(self, value):
        Entity.__init__(self, "File Hash", value, hashType)
        self.VT_url = "https://www.virustotal.com/api/v3/files/{}".format(self.value)
        self.type = hashType

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
        