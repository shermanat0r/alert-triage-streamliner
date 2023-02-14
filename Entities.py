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

    def defang(self):
        return self.name

    def format(self):
        return "{}: {}".format(self.name.upper(), self.defang())

class IP_Address(Entity):
    def __init__(self, name, value, ip_type):
        Entity.__init__(self, name, value)
        self.VT_url = "https://www.virustotal.com/api/v3/ip_addresses/{}".format(self.value)
        self.ip_type = ip_type

    def defang(self):
        defanged = self.value.replace(".", "[.]", 1)
        return defanged

    def enrich(self):
        if self.ip_type == "internal":
            self.enrichments = "Internal IP address"
        else:
            # wrapper = APIwrapper()
            # self.enrichments = wrapper.VT_lookup(self).json()
            # leaving this in so I remember where the interesting data is in the JSON, thinking I want to move this somewhere else
            # harmless = self.enrichments["data"]["attributes"]["last_analysis_stats"]["malicious"]
            # malicious = self.enrichments["data"]["attributes"]["last_analysis_stats"]["suspicious"]
            # badVotes = harmless + malicious
            return

class Port(Entity):
    def __init__(self, name, protocol, number):
        Entity.__init__(self, name, number)
        self.protocol = protocol

    def format(self):
        return "{}: {} ({})".format(self.name,self.value, self.protocol)

class FileHash(Entity):
    def __init__(self, name, value):
        Entity.__init__(self, name, value)
        self.VT_url = "https://www.virustotal.com/api/v3/files/{}".format(self.value)

    def enrich(self):
        # wrapper = APIwrapper()
        # self.enrichments = wrapper.VT_lookup(self).json()
        return

class Domain(Entity):
    def __init__(self, value):
        Entity.__init__(self, "domain", value)
        self.VT_url = "https://www.virustotal.com/api/v3/domains/{}".format(self.value)
    
    def defang(self):
        defanged = self.value.replace(".", "[.]", 1)
        return defanged

    def enrich(self):
        # wrapper = APIwrapper()
        # self.enrichments = wrapper.VT_lookup(self).json()
        return

class URL(Entity):
    def __init__(self, value):
        Entity.__init__(self, "url", value)
        self.VT_url = "https://www.virustotal.com/api/v3/domains/{}".format(self.value)

    def defang(self):
        defanged = self.value.replace(".", "[.]", 1)
        defanged = defanged.replace("http", "hxxp", 1)
        return defanged

    def enrich(self):
        # wrapper = APIwrapper()
        # self.enrichments = wrapper.VT_lookup(self).json()
        return

class Case:
    def __init__(self, name, time):
        self.name = name
        self.time = time
        self.entities = dict()

    def add_entity(self, entity):
        try:
            self.entities[entity.name] += [entity]
        except KeyError:
            self.entities[entity.name] = [entity]

    def format(self):
        for entityType in self.entities:
            # for entity in entityType:
            print(entityType.format())