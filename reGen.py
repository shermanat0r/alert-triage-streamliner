 #!/usr/env/python3.10

"""
Name: reGen.py (report generator)
Author: Caleb Bryant
Date: 2023/02/11
Description: Inspired by Zach Branch's Escalator.py, this program is a command line tool meant to streamline the process of collecting information in a security incident.
"""

import sys, re, argparse
from ipaddress import ip_address
from Entities import *
from APIwrapper import *

# regex declarations
timestamp_regex = re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
url_regex = re.compile(r'^(http|https)://\S+$')
sha256_regex = re.compile(r'^[a-fA-F0-9]{64}$')
sha1_regex = re.compile(r'^[a-fA-F0-9]{40}$')
md5_regex = re.compile(r'^[a-fA-F0-9]{32}$')

# declaring parser
parser = argparse.ArgumentParser(description='Automate security incident report writing.')

# declaring parser arguments
parser.add_argument('name', type=str, help='Name of the triggering alert')
parser.add_argument('date', type=str, help='UTC date of the event in YYYY-MM-DD format')
parser.add_argument('time', type=str, help='UTC timestamp of the event in HH:MM:SS format')
parser.add_argument('-u', '--user', type=str, help='Username')
parser.add_argument('-H', '--host', type=str, help='Hostname')
parser.add_argument('-f', '--file', type=str, help='File name')
parser.add_argument('-p', '--path', type=str, help='File path')
parser.add_argument('-a', '--hash', type=str, help='File hash')
parser.add_argument('-c', '--cmd', type=str, help='Command line')
parser.add_argument('-s', '--srcip', type=str, help='Source IP address')
parser.add_argument('-d', '--destip', type=str, help='Source IP address')
parser.add_argument('-sP', '--sport', type=int, help='Source port')
parser.add_argument('-dP', '--dport', type=int, help='Destination port')
parser.add_argument('-U', '--url', type=str, help='URL')
parser.add_argument('-D', '--domain', type=str, help='Domain name')
parser.add_argument('-j', '--jira', action='store_true', help='Create a Jira query link')
parser.add_argument('-v', '--verbose', action='count', help='Increase amount of entity info enrichment')

args = parser.parse_args()

alertName = args.name
timestamp = "{} {}".format(args.date, args.time)
user = args.user
host = args.host
fileName = args.file
filePath = args.path
fileHash = args.hash
commandLine = args.cmd
srcIp = args.srcip
destIp = args.destip
sPort = args.sport
dPort = args.dport
url = args.url
domain = args.domain
jira = args.jira
verbosity = args.verbose

try: # input validation, throw value error if any critical input is malformed
    if not re.match(timestamp_regex, timestamp):
        raise ValueError("Invalid timestamp format")

    masterCase = Case(alertName, timestamp)

    if user:
        newUser = Entity("user", user)
        masterCase.add_entity(newUser)

    if host:
        newHost = Entity("hostname", host)
        masterCase.add_entity(newHost)

    if fileName:
        newFileName = Entity("filename", fileName)
        masterCase.add_entity(newFileName)

    if filePath:
        newFilePath = Entity("filepath", filePath)
        masterCase.add_entity(newFilePath)

    if fileHash:
        sha256_error, sha1_error, md5_error = (False, False, False)
        if not re.match(sha256_regex, fileHash):
            sha256_error = True
        if not re.match(sha1_regex, fileHash):
            sha1_error = True
        if not re.match(md5_regex, fileHash):
            md5_error = True
        if sha256_error and sha1_error and md5_error:
            raise ValueError("File hash does not match sha265, sha1, or md5 formats")
        hashType = "sha256" if not sha256_error else "sha1" if not sha1_error else "md5"
        newFileHash = FileHash(hashType, fileHash)
        if verbosity == 1:
            newFileHash.enrich()
        # elif verbosity > 1:
        #     fileHash.enrich()
        masterCase.add_entity(newFileHash)

    if commandLine:
        newCommandLine = Entity("command line", commandLine)
        masterCase.add_entity(newCommandLine)

    if srcIp:
        ipType = "internal" if ip_address(srcIp).is_private else "external" # will throw a ValueError if not a valid IP address
        newSrcIp = IP_Address("source ip", srcIp, ipType)
        if verbosity == 1:
            srcIp.enrich()
        # elif verbosity > 1:
        #     srcIp.enrich()
        masterCase.add_entity(newSrcIp)

    if destIp:
        ipType = "internal" if ip_address(destIp).is_private else "external" # will throw a ValueError if not a valid IP address
        newDestIp = IP_Address("destination ip", srcIp, ipType)
        # check if IP is public or private before proceding to save on API calls
        if verbosity == 1:
            destIp.enrich()
        # elif verbosity > 1:
        #     destIp.enrich()
        masterCase.add_entity(newDestIp)

    if sPort:
        newSrcPort = Port("source port", sPort)
        masterCase.add_entity(newSrcPort)

    if dPort:
        newDestPort = Port("destination port", dPort)
        masterCase.add_entity(newDestPort)
        
    if url:
        if not re.match(url_regex, url):
            raise ValueError("Invalid URL")
        newUrl = URL(url)
        if verbosity == 1:
            newUrl.enrich()
        # elif verbosity > 1:
        #     ipAddress.enrich()
        masterCase.add_entity(newUrl)

    if domain:
        newDomain = Domain(domain)
        masterCase.add_entity(newDomain)

    if jira:
        masterCase.create_jira_query()
    
except ValueError as e:
    sys.exit(e.args)

masterCase.format()