 #!/usr/env/python3.10

"""
Name: reGen.py (report generator)
Author: Caleb Bryant
Organization: Cyderes
Date: 2023/02/11
Description: Inspired by Zach Branch's Escalator.py, this program is a command line tool meant to streamline the process of collecting information in a security incident.
"""

import re, argparse, Entities, APIwrapper

# regex declarations
timestamp_regex = re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
ip_regex = re.compile(r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
privateip_regex = re.compile(r'^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}$')
url_regex = re.compile(r'^(http|https)://\S+$')
sha256_regex = re.comile(r'^[a-fA-F0-9]{64}$')
sha1_regex = re.compile(r'^[a-fA-F0-9]{40}$')
md5_regex = re.compile(r'^[a-fA-F0-9]{32}$')

# declaring parser
parser = argparse.ArgumentParser(description='Automate security incident report writing.')

# declaring parser arguments
parser.add_argument('name', type=str, help='Name of the triggering alert')
parser.add_argument('timestamp', type=str, help='UTC timestamp of the event in YYYY-MM-DD HH:MM:SS format')
parser.add_argument('-u', '--user', type=str, help='Username')
parser.add_argument('-H', '--host', type=str, help='Hostname')
parser.add_argument('-f', '--file', type=str, help='File name')
parser.add_argument('-p', '--path', type=str, help='File path')
parser.add_argument('-a', '--hash', type=str, help='File hash')
parser.add_argument('-s', '--srcip', type=str, help='Source IP address')
parser.add_argument('-d', '--destip', type=str, help='Source IP address')
parser.add_argument('-u', '--url', type=str, help='URL')
parser.add_argument('-D', '--domain', type=str, help='Domain name')
parser.add_argument('-j', '--jira', action='store_true', help='Create a Jira query link')
parser.add_argument('-v', '--verbose', action='count', help='Increase verbosity of the output')

args = parser.parse_args()

alertName = args.name
timestamp = args.timestamp
user = args.user
host = args.host
fileName = args.file
filePath = args.path
fileHash = args.hash
srcip = args.srcip
destIp = args.destip
url = args.url
domain = args.domain
jira = args.jira
verbosity = args.verbose

# def gen_report():

try:
    raise re.error if not re.match(timestamp_regex, timestamp)
except re.error as e:
    print("Invalid timestamp format")
    exit(0)

if srcIp:
    try:
        raise re.error if not re.match(ip_regex, srcIp)
    except re.error as e:
        print("Invalid IP address")
        exit(0)
    if verbosity == 1 and not re.match(privateip_regex, srcIp):
        srcIp = Entities.IPaddr(srcIp)
        srcIp.enrich()
    # elif verbosity > 1:
    #     srcIp.enrich()

if destIp:
    try:
        raise re.error if not re.match(ip_regex, destIp)
    except re.error as e:
        print("Invalid IP address")
        exit(0)
    if verbosity == 1 and not re.match(privateip_regex, srcIp):
        destIp = Entities.IPaddr(destIp)
        destIp.enrich()
    # elif verbosity > 1:
    #     destIp.enrich()

if fileHash:
    sha256, sha1, md5 = (None, None, None)
    try:
        raise re.error if not re.match(sha256_regex, fileHash)
    except:
        sha256 = True
    try:
        raise re.error if not re.match(sha1_regex, fileHash)
    except re.error as e:
        sha1 = True
    try:
        raise re.error if not re.match(md5_regex, fileHash)
    except re.error as e:
        md5 = True
    if not (sha256 or sha1 or md5):
        print("Hash format does not match sha256, sha1, or md5")
        exit(0)
    hashType = "sha256" if sha256 else "sha1" if sha1 else "md5" if md5 else None
    fileHash = Entities.FileHash(fileHash, hashType)
    if verbosity == 1:
        fileHash.enrich()
    # elif verbosity > 1:
    #     fileHash.enrich()

if url:
    try:
        raise re.error if not re.match(url_regex, url)
    except re.error as e:
        print("Invalid URL format")
        exit(0)
    if verbosity == 1:
        url = Entities.URL(url)
        url.enrich()
    # elif verbosity > 1:
    #     ipAddress.enrich()

if jira:
    # to do: find out how the jira query urls are formatted