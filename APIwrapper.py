"""
Name: APEwrapper.py
Author: Caleb Bryant
Date: 2023/02/11
Description: Class to interact with APIs. Keeps track of API keys. API keys are meant to be kept in environment variables.
"""

import requests, os

class APIwrapper:
    def __init__(self):
        self.VT_key = os.environ.get("VIRUSTOTALAPIKEY")
        if not self.VT_key:
            print("Missing VirusTotal API Key.")
        # to do: add ability to add the API key to the environment variable
    
    def VT_lookup(self, entity):
        headers = {
            "accept": "application/json",
            "x-apikey": self.VT_key
            }
        url = entity.VT_url
        response = requests.get(url, headers=headers)
        return response
    
    # ipinfo API
    # google safebrowsing API