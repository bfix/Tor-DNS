
Tor-DNS: Simple DNS server that uses a Tor SOCKS5 proxy to resolve names 
========================================================================

(c) 2013 Bernd Fix   >Y<

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Introduction
------------

**N.B.: The functionality provided by this little application is
basically identical to what you get by setting the
*"DNSPort [address:]port|auto [isolation flags]"* parameter in your
Tor configuration file. So consider this as a hands-on experiment
for Tor proxy communication in Go.**

In case you run a torified application (using the torsocks or tsocks
helper scripts) and the application in question still uses (domain)
names to address computers on the internet, the resulting DNS queries
can jeopardize your anonymity if an adversary can monitor your DNS
queries to the nameservers.

This little DNS server uses the built-in Tor SOCKS5 functionality to
resolve names via the Tor network and therefore helps to ensure your
anonymity in the above cases.

Currently the DNS server can only handle very simple queries (like
resolving a name or reverse lookup of an IP address), but it can't
return other records than those of type "A" (IPv4 addresses), so no
"MX", "AAAA", "SOA", "NS" or "TXT"  queries are answered at all.
This is due to the limitations within the Tor proxy; whenever it is
extended, the Tor-DNS service will make use of that new query types.

Prerequisites
-------------

This application assumes you have installed Tor on your local computer
and that the local Tor relay is up and running as a SOCKS5 proxy.

A detailed help is available at <http://torproject.org>.

Install
-------

This version ot Tor-DNS is designed for the Go1 release; see
<http://golang.org> for more details.

To build an executable for your platform, change into the source directory
and type the following command:

    $ go build -o tor-dns
    
This builds the required executable that can then be run using the
following command:

    $ sudo ./tor-dns

Because the server is running on the privileged port 53 (domain) it requires
root permissions to be run.

Things to consider
------------------

* Make sure you have stopped any other DNS service on your local machine
before starting Tor-DNS.
* Make sure that Tor-DNS is used to resolve local queries by modifying the
**/etc/resolv.conf** file or whatever is appropriate on your platform.
 