#!/usr/bin/env python3
import textwrap
import argparse
import math
import os
import re
import subprocess
import sys
import urllib
import ipaddress
try:
    from IPy import IP, IPSet
    has_IPy = True
except:
    has_IPy = False
from .scholar import SCHOLAR_ROUTES
try:
    from .custom import CUSTOM_ROUTES
except:
    CUSTOM_ROUTES = []


def generate_ovpn(_, aggregate):
    results = fetch_ip_data(aggregate)

    upscript_header = textwrap.dedent("""\
        #!/bin/bash -

        export PATH="/bin:/sbin:/usr/sbin:/usr/bin"
        OLDGW=$(ip route show 0/0 | head -n1 | sed -e 's/^default//')

        ip -batch - <<EOF
        """)
    downscript_header = textwrap.dedent("""\
        #!/bin/bash -

        export PATH="/bin:/sbin:/usr/sbin:/usr/bin"
        ip -batch - <<EOF
        """)

    upfile = open('vpn-up.sh', 'w')
    downfile = open('vpn-down.sh', 'w')

    upfile.write(upscript_header)
    downfile.write(downscript_header)

    for ip, _, mask in results:
        upfile.write('route add %s/%s $OLDGW\n' % (ip, mask))
        downfile.write('route del %s/%s\n' % (ip, mask))

    upfile.write('EOF\n')
    downfile.write('EOF\n')

    upfile.close()
    downfile.close()

    os.chmod('vpn-up.sh', 0o755)
    os.chmod('vpn-down.sh', 0o755)


def generate_old(metric, aggregate):
    results = fetch_ip_data(aggregate)

    rfile = open('routes.txt', 'w')

    rfile.write('max-routes %d\n\n' % (len(results) + 20))

    for ip, mask, _ in results:
        rfile.write("route %s %s net_gateway %d\n" % (ip, mask, metric))

    rfile.close()


def generate_linux(metric, aggregate):
    results = fetch_ip_data(aggregate)

    upscript_header = textwrap.dedent("""\
        #!/bin/bash -

        OLDGW=$(ip route show 0/0 | head -n1 | grep 'via' | grep -Po '\d+\.\d+\.\d+\.\d+')

        if [ $OLDGW == '' ]; then
            exit 0
        fi

        ip -batch - <<EOF
        """)

    downscript_header = textwrap.dedent("""\
        #!/bin/bash
        export PATH="/bin:/sbin:/usr/sbin:/usr/bin"
        ip -batch - <<EOF
        """)

    upfile = open('ip-pre-up', 'w')
    downfile = open('ip-down', 'w')

    upfile.write(upscript_header)
    downfile.write(downscript_header)

    for ip, _, mask in results:
        upfile.write('route add %s/%s via $OLDGW metric %s\n' %
                     (ip, mask, metric))
        downfile.write('route del %s/%s\n' % (ip, mask))

    upfile.write('EOF\n')
    downfile.write('EOF\n')

    upfile.close()
    downfile.close()

    os.chmod('ip-pre-up', 0o0755)
    os.chmod('ip-down', 0o0755)


def generate_mac(_, aggregate):
    results = fetch_ip_data(aggregate)

    upscript_header = textwrap.dedent("""\
        #!/bin/sh
        export PATH="/bin:/sbin:/usr/sbin:/usr/bin"

        OLDGW=`netstat -nr | grep '^default' | grep -v 'ppp' | sed 's/default *\\([0-9\.]*\\) .*/\\1/'`

        if [ ! -e /tmp/pptp_oldgw ]; then
            echo "${OLDGW}" > /tmp/pptp_oldgw
        fi

        dscacheutil -flushcache
        """)

    downscript_header = textwrap.dedent("""\
        #!/bin/sh
        export PATH="/bin:/sbin:/usr/sbin:/usr/bin"

        if [ ! -e /tmp/pptp_oldgw ]; then
                exit 0
        fi

        OLDGW=`cat /tmp/pptp_oldgw`
        """)

    upfile = open('ip-up', 'w')
    downfile = open('ip-down', 'w')

    upfile.write(upscript_header)
    downfile.write(downscript_header)

    for ip, _, mask in results:
        upfile.write('route add %s/%s "${OLDGW}"\n' % (ip, mask))
        downfile.write('route delete %s/%s ${OLDGW}\n' % (ip, mask))

    downfile.write('\n\nrm /tmp/pptp_oldgw\n')

    upfile.close()
    downfile.close()

    os.chmod('ip-up', 0o755)
    os.chmod('ip-down', 0o755)


def generate_win(metric, aggregate):
    results = fetch_ip_data(aggregate)

    upscript_header = textwrap.dedent("""\
        @echo off\n
        for /F "tokens=3" %%* in ('route print ^| findstr "\\<0.0.0.0\\>"') do set "gw=%%*"
        """)

    upfile = open('vpnup.bat', 'w')
    downfile = open('vpndown.bat', 'w')

    upfile.write(upscript_header)
    upfile.write('ipconfig /flushdns\n\n')

    downfile.write("@echo off")
    downfile.write('\n')

    for ip, mask, _ in results:
        upfile.write('route add %s mask %s %s metric %d\n' %
                     (ip, mask, "%gw%", metric))
        downfile.write('route delete %s\n' % ip)

    upfile.close()
    downfile.close()


def fetch_ip_data(aggregate):
    url = 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
    if os.path.exists("delegated-apnic-latest"):
        with open("delegated-apnic-latest", "rb") as f:
            data = f.read()
    else:
        try:
            data = subprocess.check_output(['wget', url, '-O-'])
        except (OSError, AttributeError):
            print(("Fetching data from apnic.net, "
                   "it might take a few minutes, please wait..."),
                  file=sys.stderr)
            data = urllib.urlopen(url).read()

        with open("delegated-apnic-latest", 'wb') as f:
            f.write(data)

    cnregex = re.compile(r'^apnic\|cn\|ipv4\|[\d\.]+\|\d+\|\d+\|a\w*$',
                         re.I | re.M)

    cndata = cnregex.findall(str(data, encoding="utf-8"))

    results = []

    for item in cndata:
        unit_items = item.split('|')
        starting_ip = unit_items[3]
        num_ip = int(unit_items[4])

        imask = 0xffffffff ^ (num_ip - 1)
        imask = hex(imask)[2:]

        mask = [imask[i:i + 2] for i in range(0, 8, 2)]
        mask = '.'.join([str(int(i, 16)) for i in mask])

        cidr = 32 - int(math.log(num_ip, 2))

        results.append((starting_ip, mask, cidr))

    extra_routes = SCHOLAR_ROUTES + CUSTOM_ROUTES
    for item in extra_routes:
        ipnet = ipaddress.IPv4Network(item)
        results.append((
            str(ipnet.network_address),
            str(ipnet.netmask),
            ipnet.prefixlen,
        ))

    return aggregate_nets(results) if aggregate else results


def aggregate_nets(nets):
    def flush(ipset):
        for ip in ipset:
            addr, prefix = (ip.strNormal(), '32') \
                if ip.prefixlen() == 32 else \
                ip.strNormal().split('/')
            mask = ip.strNetmask()
            yield (addr, mask, prefix)

    i, limit = 0, 300
    ips = IPSet()
    for starting_ip, mask, prefix in nets:
        ip = IP("{}/{}".format(starting_ip, prefix))
        ips.add(ip)
        i += 1

        if i >= limit:
            i = 0
            yield from flush(ips)
            ips = IPSet()

    yield from flush(ips)


def main():
    parser = argparse.ArgumentParser(
        description="Generate routing rules for VPN users in China.")
    parser.add_argument('-p',
                        dest='platform',
                        default='openvpn',
                        nargs='?',
                        choices=['openvpn', 'old', 'mac', 'linux', 'win'],
                        help="target platform")

    parser.add_argument('--aggregate',
                        action='store_true',
                        help="Aggregate Routes")

    parser.add_argument('-m',
                        dest='metric',
                        default=5,
                        nargs='?',
                        type=int,
                        help="metric")

    args = parser.parse_args()

    if args.aggregate and not has_IPy:
        args.aggregate = False
        print("Route aggregation needs IPy.")

    if args.platform.lower() == 'openvpn':
        generate_ovpn(args.metric, args.aggregate)
    elif args.platform.lower() == 'old':
        generate_old(args.metric, args.aggregate)
    elif args.platform.lower() == 'linux':
        generate_linux(args.metric, args.aggregate)
    elif args.platform.lower() == 'mac':
        generate_mac(args.metric, args.aggregate)
    elif args.platform.lower() == 'win':
        generate_win(args.metric, args.aggregate)
    else:
        exit(1)

if __name__ == '__main__':
    main()
