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

# This script generates an additional pair of random server and client
# addresses for use by ns.sh. It is intended to be used by tests that
# require two separate ocserv instances and clients.

if test -z "${IPCALC}"; then
	echo "ipcalc was not found"
	exit 1
fi

ret=0
while [ $ret = 0 ]
do
	eval $(${IPCALC} -r 32 --minaddr)
	ADDRESS2=${MINADDR}
	ping ${PINGOPS} ${ADDRESS2} >/dev/null 2>&1
	ret=$?
done

ret=0
while [ $ret = 0 ]
do
	eval $(${IPCALC} -r 32 --minaddr)
	CLI_ADDRESS2=${MINADDR}
	ping ${PINGOPS} ${CLI_ADDRESS2} >/dev/null 2>&1
	ret=$?
done

echo "**************************"
echo "Client address2: $CLI_ADDRESS2"
echo "Server address2: $ADDRESS2"
echo "**************************"
