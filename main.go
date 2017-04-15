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
 * (c) 2017 Michał Trojnara <Michal.Trojnara@stunnel.org>
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
	"time"
)

var (
	flVerbose    = flag.Bool("v", false, "verbose output")
	flDebug      = flag.Bool("D", false, "debug output")
	flDnsPort    = flag.String("p", ":53", "the UDP port to listen for DNS requests on")
	flSocksProxy = flag.String("s", ":9050", "the SOCKSv5 proxy to resolve names via")
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

	srv_addr, err := net.ResolveUDPAddr("udp4", *flDnsPort)
	if err != nil {
		return fmt.Errorf("[Tor-DNS] Can't resolve service address: " + err.Error())
	}

	conn, err := net.ListenUDP("udp4", srv_addr)
	if err != nil {
		return fmt.Errorf("[Tor-DNS] Can't listen on service port: " + err.Error())
	}
	defer conn.Close()

	c := make(chan packet)
	for i := 0; i < 5; i++ {
		go worker(conn, c)
	}

	for {
		buf := make([]byte, 2048)
		n, addr, err := conn.ReadFrom(buf)
		if err == nil {
			var pkt packet
			pkt.addr = addr
			pkt.buf = buf[:n]
			c <- pkt
		}
	}

	return nil
}

type packet struct {
	addr net.Addr
	buf  []byte
}

/*
 * DNS request/response data structures:
 * This assumes that each query returns one (or none) result.
 * - query opcode (0 for QUERY, 1 for IQUERY)
 * - query parameters (name/addr, type and class for names)
 * - response values (name/addr)
 */
type query struct {
	pkt    *packet
	id     int
	opcode int
	name   string
	addr   net.IP
	typ    int
	class  int
}

type result struct {
	q     *query
	valid bool
	typ   int
	name  string
	addr  net.IP
}

func worker(dns_conn *net.UDPConn, c <-chan packet) {
	for {
		socks_conn, err := net.Dial("tcp4", *flSocksProxy)
		for err != nil {
			fmt.Println("[Tor-DNS] failed to connect to Tor proxy server: " + err.Error())
			time.Sleep(time.Second * 1)
			socks_conn, err = net.Dial("tcp4", *flSocksProxy)
		}
		defer socks_conn.Close()

		q, ok := disassemble(<-c)
		for !ok {
			q, ok = disassemble(<-c)
		}

		if r, err := answer(socks_conn, q); err == nil {
			dns_conn.WriteTo(assemble(r), q.pkt.addr)
		} else {
			fmt.Printf("[Tor-DNS] Can't answer query %x: %s\n", q.id, err.Error())
		}
	}
}

/*
 * Handle incoming DNS packet:
 * - Only handle requests with at least one query resource record and
 *   empty response resource records; skip all other packets.
 */
func disassemble(pkt packet) (q query, ok bool) {
	var pos, id, flags int
	id, pos = getShort(pkt.buf, pos)
	flags, pos = getShort(pkt.buf, pos)
	opcode := (flags >> 11) & 0xF
	if opcode > 1 {
		if *flVerbose {
			fmt.Printf("[Tor-DNS] Request has unsupported Opcode: %d\n", opcode)
		}
		return
	}

	var qd_cnt, an_cnt, ns_cnt, ar_cnt int
	qd_cnt, pos = getShort(pkt.buf, pos)
	an_cnt, pos = getShort(pkt.buf, pos)
	ns_cnt, pos = getShort(pkt.buf, pos)
	ar_cnt, pos = getShort(pkt.buf, pos)

	if ar_cnt > 0 {
		if *flVerbose {
			fmt.Printf("[Query:%x] Request has %d Additional RRs, but that is not supported\n", id, ar_cnt)
		}
	}
	if an_cnt > 0 || ns_cnt > 0 || qd_cnt != 1 {
		if *flVerbose {
			fmt.Printf("[Tor-DNS] Request has invalid counts: (%d,%d,%d)\n", qd_cnt, an_cnt, ns_cnt)
		}
		return
	}

	q.pkt = &pkt
	q.id = id
	q.opcode = opcode
	name, num := read_name(pkt.buf[pos:])
	q.name = name
	pos += num
	q.typ, pos = getShort(pkt.buf, pos)
	q.class, pos = getShort(pkt.buf, pos)
	ok = true
	return
}

/*
 * Assemble DNS response from list of Tor SOCKS responses.
 */
func assemble(r result) []byte {
	buf := make([]byte, 2048)
	flags := 0x8180 // QR|RD|RA
	num := 0
	if r.valid {
		num = 1
	} else {
		flags |= 3 // NXDOMAIN
	}

	// Header
	pos := setShort(buf, 0, r.q.id) // ID
	pos = setShort(buf, pos, flags)
	pos = setShort(buf, pos, 1) // QDCOUNT
	pos = setShort(buf, pos, num) // ANCOUNT
	pos = setShort(buf, pos, 0) // NSCOUNT
	pos = setShort(buf, pos, 0) // ARCOUNT

	// Question
	name_start := pos
	pos = write_name(buf, pos, r.q.name) // QNAME
	pos = setShort(buf, pos, r.q.typ) // QTYPE
	pos = setShort(buf, pos, r.q.class) // QCLASS

	// Answer
	if r.valid {
		pos = setShort(buf, pos, 0xC000|name_start) // NAME
		if r.typ == 1 { // SOCKS5 IP v4 address
			pos = setShort(buf, pos, 1) // TYPE := A
		} else {
			pos = setShort(buf, pos, r.q.typ) // TYPE := requested
		}
		pos = setShort(buf, pos, r.q.class) // CLASS
		pos = setShort(buf, pos, 0) // TTL high
		pos = setShort(buf, pos, 900) // TTL low (15 minutes)
		rdlength := pos
		pos += 2 // Fill RDLENGTH later
		idx := pos
		if r.typ == 1 { // SOCKS5 IP v4 address
			for i, v := range r.addr {
				buf[pos+i] = v
			}
			pos += 4
		} else {
			pos = write_name(buf, pos, r.name)
		}
		setShort(buf, rdlength, pos-idx) // RDLENGTH
	}

	if *flDebug {
		fmt.Println("!!! " + hex.EncodeToString(buf[:pos]))
	}
	return buf[:pos]
}

/*
 * Use the Tor SOCKS5 proxy to resolve names:
 * Simple approach - one query returns exactly one result (or none at all)
 * - normal queries (op=0) pass a name and (usually) request a ip-addr
 *   (reverse queries can be name-based with names of the form
 *   "a.b.c.d.in-addr.arpa"; this yields a name instead of an ip-addr)
 * - reverse queries (op=1) pass an ip-addr and request a name
 */
func answer(conn net.Conn, q query) (r result, err error) {
	buf := make([]byte, 128)
	r.q = &q
	r.valid = false

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
		if q.opcode == 0 {
			fmt.Printf("[Query:%x] %s\n", q.id, q.name)
		} else {
			fmt.Printf("[Query:%x] %s\n", q.id, q.addr.String())
		}
	}

	size := 0
	buf[0] = 5
	// FIXME: IQUERY has been obsoleted by RFC 3425 (November 2002)
	// Tor [F1] extension should handle PTR requests instead
	if q.opcode == 0 {
		buf[1] = 0xF0
	} else {
		buf[1] = 0xF1
	}
	buf[2] = 0
	if q.opcode == 0 { // QUERY
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
	} else { // IQUERY
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
		fmt.Printf("[Tor-DNS] Tor proxy request failure for query %x: %s\n", q.id, err.Error())
		return
	}
	if n != size {
		err = errors.New("Size mismtach")
		fmt.Printf("[Tor-DNS] Tor proxy request failure for query %x: %s\n", q.id, err.Error())
		return
	}
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Printf("[Tor-DNS] Tor proxy response failure for query %x: %s\n", q.id, err.Error())
		return
	}
	if buf[1] != 0 {
		fmt.Printf("[Tor-DNS] Tor proxy response failure for query %x: %d\n", q.id, int(buf[1])&0xFF)
		return
	}

	if *flDebug {
		fmt.Println(">>> " + hex.EncodeToString(buf[:n]))
	}

	r.typ = int(buf[3]) & 0xFF
	if r.typ == 1 { // SOCKS5 IP v4 address
		r.addr = buf[4:8]
		if *flVerbose {
			fmt.Printf("[Response:%x] %s\n", q.id, r.addr.String())
		}
	} else if r.typ == 3 { // SOCKS5 DOMAINNAME
		len := int(buf[4]) & 0xFF
		r.name = string(buf[5 : len+5])
		if *flVerbose {
			fmt.Printf("[Response:%x] %s\n", q.id, r.name)
		}
	} else {
		len := int(buf[4]) & 0xFF
		r.name = string(buf[5 : len+5])
		if *flVerbose {
			fmt.Printf("[Response:%x:%d] %s\n", q.id, r.typ, hex.EncodeToString([]byte(r.name)))
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
