package main

import (
	"log"
	"net"
)

func handleDNSRequest(conn net.PacketConn, addr net.Addr, query []byte) {
	// 伪造的 IP 地址响应
	const demoNetResponse = "\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00\x03\x64\x65\x6d\x6f\x03\x6e\x65\x74\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"

	// 检查是否是对 demo.net 的查询
	if string(query[len(query)-12:]) == "\x03\x64\x65\x6d\x6f\x03\x6e\x65\x74\x00\x00\x01" {
		conn.WriteTo([]byte(demoNetResponse), addr)
		return
	}

	// 否则转发到 8.8.8.8
	googleDNS := "8.8.8.8:53"
	udpAddr, _ := net.ResolveUDPAddr("udp", googleDNS)
	dnsConn, _ := net.DialUDP("udp", nil, udpAddr)
	defer dnsConn.Close()

	dnsConn.Write(query)
	buffer := make([]byte, 1024)
	n, _, _ := dnsConn.ReadFrom(buffer)

	conn.WriteTo(buffer[:n], addr)
}

func DnsServe() {

	serverAddr := "0.0.0.0:54"
	udpAddr, _ := net.ResolveUDPAddr("udp", serverAddr)
	conn, _ := net.ListenUDP("udp", udpAddr)
	defer conn.Close()

	log.Println("DNS server running on", serverAddr)

	for {
		buffer := make([]byte, 512)
		n, addr, _ := conn.ReadFrom(buffer)
		go handleDNSRequest(conn, addr, buffer[:n])
	}
}
