#!/bin/bash
#
# Copyright (C) 2023 Nikos Mavrogiannopoulos
#
# This file is part of ocserv.
#
# ocserv is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# ocserv is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This script generates a pair of random client and server addresses and
# two (IPv4+IPv6) random network addresses for use with the VPN;
# it sets variables needs by ns.sh. For tests that need two server
# sets include additionally random-net2.sh

IPCALC=$(which ipcalc-ng 2>/dev/null)
if test -z "${IPCALC}"; then
	IPCALC=$(which ipcalc 2>/dev/null)
fi

if test -z "${IPCALC}"; then
	echo "ipcalc was not found"
	exit 1
fi

PINGOPS="-W 1 -c 2"

# Generate random IPv4 VPN network
ret=0
while [ $ret = 0 ]
do
	eval $(${IPCALC} -r 24 -np --minaddr)
	VPNNET="${NETWORK}/${PREFIX}"
	VPNADDR=${MINADDR}
	ping ${PINGOPS} ${VPNADDR} >/dev/null 2>&1
	ret=$?
done

# Generate random IPv6 VPN network
ret=0
while [ $ret = 0 ]
do
	eval $(${IPCALC} -r 112 -np --minaddr)
	VPNNET6="${NETWORK}/${PREFIX}"
	VPNADDR6="${NETWORK}1"
	ping ${PINGOPS} ${VPNADDR6} >/dev/null 2>&1
	ret=$?
done

# Generate random IPv4 addresses for the client and server
ret=0
while [ $ret = 0 ]
do
	eval $(${IPCALC} -r 32 --minaddr)
	ADDRESS=${MINADDR}
	ping ${PINGOPS} ${ADDRESS} >/dev/null 2>&1
	ret=$?
done

ret=0
while [ $ret = 0 ]
do
	eval $(${IPCALC} -r 32 --minaddr)
	CLI_ADDRESS=${MINADDR}
	ping ${PINGOPS} ${CLI_ADDRESS} >/dev/null 2>&1
	ret=$?
done

echo "**************************"
echo "VPN IPv4 network: $VPNNET"
echo "VPN IPv4 server address: $VPNADDR"
echo "VPN IPv6 network: $VPNNET6"
echo "VPN IPv6 server address: $VPNADDR6"
echo "Client address: $CLI_ADDRESS"
echo "Server address: $ADDRESS"
echo "**************************"
