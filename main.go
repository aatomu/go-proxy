package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"syscall"
)

func main() {
	server, err := net.Listen("tcp", ":1034")
	log.Println("TCP server listen", err)

	for {
		log.Println("TCP conn waiting...", err)
		conn, err := server.Accept()
		log.Println("TCP conn accept", err)

		client := conn.RemoteAddr().(*net.TCPAddr)
		dialer := net.Dialer{LocalAddr: client}
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			var syscallErr error
			err := c.Control(func(fd uintptr) {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setSocketOption(IPPROTO_IP, IP_TRANSPARENT, 1): %w", syscallErr)
					return
				}

				syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setSocketOption(SOL_SOCKET, SO_REUSEADDR, 1): %w", syscallErr)
					return
				}

				if network == "tcp6" {
					syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
					if syscallErr != nil {
						syscallErr = fmt.Errorf("setSocketOption(IPPROTO_IP, IPV6_ONLY, 0): %w", syscallErr)
						return
					}
				}
			})

			if err != nil {
				return err
			}
			return syscallErr
		}

		remote, err := dialer.Dial("tcp", "localhost:1024")
		go io.Copy(remote, conn)
		w, err := io.Copy(conn, remote)
		log.Println("remote=>conn", w, err)
	}
}

func makeHeader(client net.Conn, proxy net.Conn, version int) []byte {
	buf := []byte{}
	local := client.RemoteAddr().(*net.TCPAddr)
	remote := proxy.RemoteAddr().(*net.TCPAddr)

	switch version {
	case 1:
		buf = append(buf, []byte{0x50, 0x52, 0x4F, 0x58, 0x59}...)
		buf = append(buf, []byte{0x20}...)
		buf = append(buf, []byte{0x54, 0x43, 0x50, 0x34}...)
		buf = append(buf, []byte{0x20}...)
		buf = append(buf, []byte(local.IP.String())...)
		buf = append(buf, []byte{0x20}...)
		buf = append(buf, []byte(remote.IP.String())...)
		buf = append(buf, []byte{0x20}...)
		buf = append(buf, []byte(fmt.Sprintf("%d", local.Port))...)
		buf = append(buf, []byte{0x20}...)
		buf = append(buf, []byte(fmt.Sprintf("%d", remote.Port))...)
		buf = append(buf, []byte{0x0d, 0x0a}...)

	case 2:
		// [0:11] Proxy protocol v2 const header
		buf = append(buf, 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A)
		// [12:12] version/command
		// version: highest 4bit= v2(0x2?)
		// command: lowest  4bit= LOCAL(0x?0),PROXY(0x?1)
		buf = append(buf, 0x21)
		// [13:13] address family/protocol
		// family  : hightest 4bit= AF_UNSPEC(0x0?),AF_INET(0x1?),AF_INET6(0x2?),AF_UNIX(0x3?)
		// protocol: lowest   4bit= UNSPEC(0x?0),STREAM(0x?1),DGRAM(0x?2)
		buf = append(buf, 0x11)
		// [14:15] body length(network endian)
		// IPv4 len = 12
		buf = binary.BigEndian.AppendUint16(buf, 12)
		// [16:28] body length(network endian)
		// 4byte Uint32 src_addr
		// 4byte Uint32 dst_addr
		// 2byte Uint16 src_port
		// 2byte Uint16 dst_port
		local := client.RemoteAddr().(*net.TCPAddr)
		remote := proxy.RemoteAddr().(*net.TCPAddr)
		buf = append(buf, local.IP.To4()...)
		buf = append(buf, remote.IP.To4()...)
		buf = binary.BigEndian.AppendUint16(buf, uint16(local.Port))
		buf = binary.BigEndian.AppendUint16(buf, uint16(remote.Port))
	}
	fmt.Printf("Binary: %x\n\t%s\n", buf, buf)
	return buf
}
