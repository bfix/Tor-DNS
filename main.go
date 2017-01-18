/*
 * Run simple DNS service loop:
 * - listen for incoming UDP4 packets on localhosts port 53 (domain).
 * - parse request and filter for simple DNS resolve queries (one query
 *   per request, one result per response)
 * - forward valid requests to the Tor SOCKS5 proxy running on
 *   localhost:9050 (default).
 * - send the response from the Tor resolver back to the requesting
 *   client.
 *
 * (c) 2013 Bernd Fix   >Y<
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
)

var (
	flVerbose = flag.Bool("v", false, "verbose output")
	flDebug   = flag.Bool("D", false, "debug output")
)

// Run a simple DNS service on port 53 (domain) at localhost.
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// returned errors mean to exit non-zero
func run() error {
	flag.Parse()

	buf := make([]byte, 2048)

	srv_addr, err := net.ResolveUDPAddr("udp4", ":53")
	if err != nil {
		return fmt.Errorf("[Tor-DNS] Can't resolve service address: " + err.Error())
	}

	conn, err := net.ListenUDP("udp4", srv_addr)
	if err != nil {
		return fmt.Errorf("[Tor-DNS] Can't listen on service port: " + err.Error())
	}
	defer conn.Close()

	for {
		n, cl_addr, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		go process(conn, cl_addr, buf, n)
	}

	return nil
}

/*
 * DNS request/response data structures:
 * This assumes that each query returns one (or none) result.
 * - query mode (forward, reverse)
 * - query parameters (name/addr, type and class for names)
 * - response values (name/addr)
 */
type query struct {
	mode  int
	name  string
	addr  net.IP
	typ   int
	class int
}

type result struct {
	q     *query
	valid bool
	typ   int
	name  string
	addr  net.IP
}

/*
 * Handle incoming DNS packet:
 * - Only handle requests with at least on query resource record and
 *   empty response resource records; skip all other packets.
 */
func process(conn *net.UDPConn, addr net.Addr, buf []byte, n int) {

	var pos, id, qtype int
	id, pos = getShort(buf, pos)
	qtype, pos = getShort(buf, pos)
	if (qtype & 0x8000) != 0 {
		if *flVerbose {
			fmt.Printf("[Tor-DNS] Request is not a standard query: %x\n", qtype)
		}
		return
	}
	mode := (qtype >> 11) & 0xF
	if mode > 1 {
		if *flVerbose {
			fmt.Printf("[Tor-DNS] Request is not a standard type: %x\n", qtype)
		}
		return
	}

	var qd_cnt, an_cnt, ns_cnt, ar_cnt int
	qd_cnt, pos = getShort(buf, pos)
	an_cnt, pos = getShort(buf, pos)
	ns_cnt, pos = getShort(buf, pos)
	ar_cnt, pos = getShort(buf, pos)

	if an_cnt > 0 || ns_cnt > 0 || ar_cnt > 0 || qd_cnt != 1 {
		if *flVerbose {
			fmt.Printf("[Tor-DNS] Request has invalid counts: (%d,%d,%d,%d)\n", qd_cnt, an_cnt, ns_cnt, ar_cnt)
		}
		return
	}

	var q query
	q.mode = mode
	name, num := read_name(buf[pos:])
	q.name = name
	pos += num
	q.typ, pos = getShort(buf, pos)
	q.class, pos = getShort(buf, pos)

	r, err := answer(id, q)
	if err != nil {
		fmt.Printf("[Tor-DNS] Can't answer query %x: %s\n", id, err.Error())
		return
	}
	if n = assemble(buf, id, r); n > 0 {
		conn.WriteTo(buf[:n], addr)
	}
}

/*
 * Assemble DNS response from list of Tor SOCKS responses.
 */
func assemble(buf []byte, id int, r result) int {

	num := 0
	if r.valid {
		num = 1
	}

	pos := setShort(buf, 0, id)
	pos = setShort(buf, pos, 0x8180)
	pos = setShort(buf, pos, 1)
	pos = setShort(buf, pos, num)
	pos = setShort(buf, pos, 0)
	pos = setShort(buf, pos, 0)

	name_start := pos
	pos = write_name(buf, pos, r.q.name)
	pos = setShort(buf, pos, r.q.typ)
	pos = setShort(buf, pos, r.q.class)

	if r.valid {
		pos = setShort(buf, pos, 0xC000|name_start)
		pos = setShort(buf, pos, r.q.typ)
		pos = setShort(buf, pos, r.q.class)
		pos = setShort(buf, pos, 0)
		pos = setShort(buf, pos, 900)
		if r.typ == 1 {
			pos = setShort(buf, pos, 4)
			for i, v := range r.addr {
				buf[pos+i] = v
			}
			pos += 4
		} else {
			idx := pos
			pos = setShort(buf, pos, 0)
			pos = write_name(buf, pos, r.name)
			setShort(buf, idx, pos-idx-2)
		}
	}

	if *flDebug {
		fmt.Println("!!! " + hex.EncodeToString(buf[:pos]))
	}
	return pos
}

/*
 * Use the Tor SOCKS5 proxy to resolve names:
 * Simple approach - one query returns exactly one result (or none at all)
 * - normal queries (op=0) pass a name and (usually) request a ip-addr
 *   (reverse queries can be name-based with names of the form
 *   "a.b.c.d.in-addr.arpa"; this yields a name instead of an ip-addr)
 * - reverse queries (op=1) pass an ip-addr and request a name
 */
func answer(id int, q query) (r result, err error) {

	buf := make([]byte, 128)
	r.q = &q
	r.valid = false

	conn, err := net.Dial("tcp4", ":9050")
	if err != nil {
		fmt.Println("[Tor-DNS] failed to connect to Tor proxy server: " + err.Error())
		return
	}
	defer conn.Close()

	buf[0] = 5
	buf[1] = 1
	buf[2] = 0
	n, err := conn.Write(buf[:3])
	if n != 3 || err != nil {
		fmt.Println("[Tor-DNS] failed to write to Tor proxy server: " + err.Error())
		return
	}
	n, err = conn.Read(buf)
	if n != 2 || err != nil {
		fmt.Println("[Tor-DNS] failed to read from Tor proxy server: " + err.Error())
		return
	}
	if buf[0] != 5 || buf[1] == 0xFF {
		fmt.Println("[Tor-DNS] Tor proxy server refuses non-authenticated connection.")
		err = errors.New("Failed authentication")
		return
	}

	if *flVerbose {
		if q.mode == 0 {
			fmt.Printf("[Query:%x] %s\n", id, q.name)
		} else {
			fmt.Printf("[Query:%x] %s\n", id, q.addr.String())
		}
	}

	size := 0
	buf[0] = 5
	if q.mode == 0 {
		buf[1] = 0xF0
	} else {
		buf[1] = 0xF1
	}
	buf[2] = 0
	if q.mode == 0 {
		dn := []byte(q.name)
		num := len(dn)
		buf[3] = 3
		buf[4] = byte(num)
		for i, v := range dn {
			buf[5+i] = v
		}
		buf[5+num] = 0
		buf[6+num] = 0
		size = num + 7
	} else {
		if len(q.addr) > 4 {
			return
		}
		buf[3] = 1
		for i, v := range q.addr {
			buf[4+i] = v
		}
		buf[8] = 0
		buf[9] = 0
		size = 10
	}

	if *flDebug {
		fmt.Println("<<< " + hex.EncodeToString(buf[:size]))
	}

	n, err = conn.Write(buf[:size])
	if err != nil {
		fmt.Printf("[Tor-DNS] Tor proxy request failure for query %x: %s\n", id, err.Error())
		return
	}
	if n != size {
		err = errors.New("Size mismtach")
		fmt.Printf("[Tor-DNS] Tor proxy request failure for query %x: %s\n", id, err.Error())
		return
	}
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Printf("[Tor-DNS] Tor proxy response failure for query %x: %s\n", id, err.Error())
		return
	}
	if buf[1] != 0 {
		fmt.Printf("[Tor-DNS] Tor proxy response failure for query %x: %d\n", id, int(buf[1])&0xFF)
		return
	}

	if *flDebug {
		fmt.Println(">>> " + hex.EncodeToString(buf[:n]))
	}

	r.typ = int(buf[3]) & 0xFF
	if r.typ == 1 {
		r.addr = buf[4:8]
		if *flVerbose {
			fmt.Printf("[Response:%x] %s\n", id, r.addr.String())
		}
	} else if r.typ == 3 {
		len := int(buf[4]) & 0xFF
		r.name = string(buf[5 : len+5])
		if *flVerbose {
			fmt.Printf("[Response:%x] %s\n", id, r.name)
		}
	}
	r.valid = true
	return
}

/*
 * Get an unsigned short value from two bytes at given position in an
 * array. Values are stored in network byte order (big endian).
 */
func getShort(buf []byte, pos int) (int, int) {
	val := (256 * (int(buf[pos]) & 0xFF)) + (int(buf[pos+1]) & 0xFF)
	return val, pos + 2
}

/*
 * Set an unsigned short value at a given position in a byte array.
 * Values are stored in network byte order (big endian).
 */
func setShort(buf []byte, pos, val int) int {
	buf[pos] = byte((val >> 8) & 0xFF)
	buf[pos+1] = byte(val & 0xFF)
	return pos + 2
}

/*
 * Read a name from a DNS resource record. Names can be stored in a
 * hierarchical structure where parts of the name are referenced
 * (part of a different name).
 */
func read_name(buf []byte) (string, int) {

	name := ""
	pos := 0
	len := int(buf[pos]) & 0xFF
	pos++
	first := true
	for len > 0 {
		if first {
			first = false
		} else {
			name += "."
		}
		tag := len >> 6
		len &= 0x3F
		if tag == 0 {
			name += string(buf[pos : pos+len])
			pos += len
			len = int(buf[pos]) & 0xFF
			pos++
		} else if tag == 3 {
			ofs := 256*len + int(buf[pos])&0xFF
			subname, _ := read_name(buf[ofs:])
			name += subname
			len = 0
		}
	}
	return name, pos
}

/*
 * Write name to DNS resource record (response).
 * Do not use funny optimization schemes like referencing sub-strings
 * within other names - just write a plain name in DNS convention.
 */
func write_name(buf []byte, pos int, name string) int {
	for len(name) > 0 {
		idx := strings.IndexRune(name, '.')
		if idx == -1 {
			idx = len(name)
		}
		buf[pos] = byte(idx)
		pos++
		for i := 0; i < idx; i++ {
			buf[pos+i] = byte(name[i])
		}
		pos += idx
		if idx == len(name) {
			break
		}
		name = string(name[idx+1:])
	}
	buf[pos] = 0
	return pos + 1
}
