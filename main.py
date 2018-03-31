#!/usr/bin/python
import sys
import socket
import os
import re
from socket import AF_INET, SOCK_STREAM
from subprocess import Popen, PIPE


RIRs = [
    'whois.ripe.net',  # Europe
    'whois.arin.net',  # America
    'whois.apnic.net',  # Asia-Pacific
    'whois.lacnic.net',  # Latin America
    'whois.afrinic.net']  # Africa
find_asn = re.compile('origin:[ ]+(.+)')
find_county = re.compile('country:[ ]+(.+)')
find_provider = re.compile('descr:[ ]+(.+)')


def main(config_file_name):
    dest_addr = ''
    try:
        with open(os.path.join(config_file_name), 'r') as config:
            dest_addr = config.readline()
    except IOError:
        sys.stderr.write('Not correct path or file is not supported: {0}\n'
                         .format(config_file_name))
        sys.exit()
    try:
        dest_addr = socket.gethostbyname(dest_addr)
    except socket.error:
        sys.stderr.write('Can not find host of {0}\n'
                         .format(dest_addr))
        sys.exit()
    addresses = get_traceroute_addresses(dest_addr)
    if len(addresses) == 0:
        addresses.append(dest_addr)
    for i in range(len(addresses)):
        info = get_domain_info(addresses[i])
        print('Number: {0}\n'
              '\r    IP: {1}\n'
              '\r    AS: {2}\n'
              '\r    Country: {3}\n'
              '\r    Provider: {4}'.format(
               i, addresses[i], info['asn'], info['country'], info['provider']))


def get_traceroute_addresses(dest_addr):
    addresses = []
    p = Popen(['tracert', dest_addr], stdout=PIPE)
    line_num = 0
    while True:
        line = p.stdout.readline()
        if not line:
            break
        parsed_line = str(line).split()
        if line_num > 3 and len(parsed_line) > 6 \
                and parsed_line[len(parsed_line) - 3] != 'Request':
            addr = parsed_line[len(parsed_line) - 2]
            addr = addr.replace('[', '')
            addr = addr.replace(']', '')
            addresses.append(addr)
        line_num += 1
    return addresses


def get_domain_info(domain_addr):
    for server in RIRs:
        data = whois_request(domain_addr, server)
        parsed_data = parse_data(data)
        if parsed_data['asn'] != '-':
            break
    return parsed_data


def parse_data(data):
    parsed_data = dict()
    country = re.search(find_county, data)
    asn = re.search(find_asn, data)
    provider = re.search(find_provider, data)
    parsed_data['country'] = country.group(1) if country is not None else '-'
    parsed_data['asn'] = asn.group(1) if asn is not None else '-'
    parsed_data['provider'] = provider.group(1) if provider is not None else '-'
    return parsed_data


def whois_request(dest_addr, server, port=43):
    sock = socket.socket(AF_INET, SOCK_STREAM)
    sock.connect((server, port))
    sock.send(("{0}\r\n".format(dest_addr)).encode("utf-8"))
    buffer = b''
    while True:
        data = ''
        try:
            data = sock.recv(1024)
        except socket.error:
            break
        if len(data) == 0:
            break
        buffer += data
    sock.close()
    return buffer.decode("utf-8")


if __name__ == "__main__":
    main("config.txt")
