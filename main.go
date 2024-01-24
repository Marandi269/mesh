package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/inbound"
	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/nat"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	icontext "github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/listener"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel/statistic"
	"github.com/vishvananda/netlink"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	"go.uber.org/atomic"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"
)

var (
	tcpQueue  = make(chan C.ConnContext, 200)
	udpQueue  = make(chan *inbound.PacketAdapter, 200)
	natTable  = nat.New()
	rules     []C.Rule
	proxies   = make(map[string]C.Proxy)
	providers map[string]provider.ProxyProvider
	configMux sync.RWMutex

	// default timeout for UDP session
	udpTimeout = 60 * time.Second

	// experimental feature
	UDPFallbackMatch = atomic.NewBool(false)
)

func lookupIP(address string) ([]net.IP, error) {
	allIPs, err := net.LookupIP(address)
	if err != nil {
		return nil, err
	}

	var ipv4IPs []net.IP
	for _, ip := range allIPs {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipv4IPs = append(ipv4IPs, ipv4)
		}
	}

	return ipv4IPs, nil
}

func getGateway() *netlink.Route {
	// 获取路由表
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		fmt.Println("Failed to get routes:", err)
		return nil
	}

	// 遍历路由，寻找默认路由
	for _, route := range routes {
		// 默认路由的目的地地址为 nil
		if route.Dst == nil {
			return &route
		}
	}
	return nil
}

func addRoute(ip net.IP, gateway net.IP) *netlink.Route {
	route := &netlink.Route{
		Dst: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		},
		Gw: gateway,
	}
	err := netlink.RouteAdd(route)
	if err != nil {
		fmt.Println("RouteAdd error:", err)
	}
	return route
}

func main() {
	buf, _ := os.ReadFile("./data/config.yaml")
	rawCfg, err := config.UnmarshalRawConfig(buf)
	if err != nil {
		return
	}

	ports := listener.Ports{
		MixedPort: 7451,
	}
	listener.SetAllowLan(true)
	listener.ReCreatePortsListeners(ports, tcpQueue, udpQueue)
	//listener.PatchTunnel(nil, tcpQueue, udpQueue)
	mapping := map[string]any{
		"name":             "x1.0 美西 - 中转5",
		"type":             "trojan",
		"server":           "7c610710-i.2nvx.com",
		"port":             10246,
		"password":         "rnjranyA",
		"udp":              true,
		"sni":              "7c610710-i.2nvx.com",
		"skip-cert-verify": false,
	}
	proxy, _ := adapter.ParseProxy(mapping)
	proxies["GLOBAL"] = proxy
	go process()

	key := new(engine.Key)
	key.Device = "utun15"
	key.Proxy = "socks5://127.0.0.1:7451"
	key.LogLevel = "info"
	key.Interface = "enp0s1"

	engine.Insert(key)

	engine.Start()
	defer engine.Stop()
	setIp()

	gateway := getGateway()
	fmt.Println("gateway:", gateway)

	proxyIps := map[string][]net.IP{}

	ps := make([]C.Proxy, 0, len(rawCfg.Proxy))
	for _, mapping := range rawCfg.Proxy {
		proxy, _ := adapter.ParseProxy(mapping)
		server, _ := mapping["server"].(string)
		ips, _ := lookupIP(server)
		proxyIps[server] = ips
		ps = append(ps, proxy)
	}

	tunGateway := net.ParseIP("192.168.0.1")
	if gateway == nil {
		fmt.Println("Invalid gateway IP")
		return
	}
	route := &netlink.Route{
		Dst:      nil,
		Gw:       tunGateway,
		Priority: gateway.Priority - 1,
	}

	if err := netlink.RouteAdd(route); err != nil {
		fmt.Printf("Failed to add default route: %v\n", err)
		return
	}
	routes := []*netlink.Route{
		route,
	}

	for key, ips := range proxyIps {
		fmt.Printf("%s:\n", key)
		for _, ip := range ips {
			fmt.Println("  ", ip)
			route := addRoute(ip, gateway.Gw)
			if route != nil {
				routes = append(routes, route)
			}
		}
	}
	defer func() {
		for _, route := range routes {
			if err := netlink.RouteDel(route); err != nil {
				//fmt.Printf("Failed to delete route for %s: %v\n", err)
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func setIp() {
	// 找到 utun15 接口
	iface, err := netlink.LinkByName("utun15")
	if err != nil {
		fmt.Println("Error getting interface:", err)
		return
	}

	if err := netlink.LinkSetUp(iface); err != nil {
		fmt.Println("Error setting interface utun15 up:", err)
		return
	}

	fmt.Println("Interface utun15 set up successfully")

	// 解析 IP 地址和子网掩码
	ipNet := &net.IPNet{
		IP:   net.ParseIP("192.168.0.1"),
		Mask: net.CIDRMask(24, 32),
	}

	// 为接口添加地址
	err = netlink.AddrAdd(iface, &netlink.Addr{IPNet: ipNet})
	if err != nil {
		fmt.Println("Error adding address:", err)
		return
	}

	fmt.Println("Address added successfully")
}

func process() {
	numUDPWorkers := 4
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}
	for i := 0; i < numUDPWorkers; i++ {
		go processUDP()
	}

	queue := tcpQueue
	for conn := range queue {
		go handleTCPConn(conn)
	}
}

func processUDP() {
	queue := udpQueue
	for conn := range queue {
		handleUDPConn(conn)
	}
}

func handleUDPConn(packet *inbound.PacketAdapter) {
	metadata := packet.Metadata()
	if !metadata.Valid() {
		packet.Drop()
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	// make a fAddr if request ip is fakeip
	var fAddr netip.Addr
	if resolver.IsExistFakeIP(metadata.DstIP) {
		fAddr, _ = netip.AddrFromSlice(metadata.DstIP)
		fAddr = fAddr.Unmap()
	}

	//if err := preHandleMetadata(metadata); err != nil {
	//	packet.Drop()
	//	log.Debugln("[Metadata PreHandle] error: %s", err)
	//	return
	//}

	// local resolve UDP dns
	if !metadata.Resolved() {
		ips, err := resolver.LookupIP(context.Background(), metadata.Host)
		if err != nil {
			packet.Drop()
			return
		} else if len(ips) == 0 {
			packet.Drop()
			return
		}
		metadata.DstIP = ips[0]
	}

	key := packet.LocalAddr().String()

	handle := func() bool {
		pc := natTable.Get(key)
		if pc != nil {
			handleUDPToRemote(packet, pc, metadata)
			return true
		}
		return false
	}

	if handle() {
		packet.Drop()
		return
	}

	lockKey := key + "-lock"
	cond, loaded := natTable.GetOrCreateLock(lockKey)

	go func() {
		defer packet.Drop()

		if loaded {
			cond.L.Lock()
			cond.Wait()
			handle()
			cond.L.Unlock()
			return
		}

		defer func() {
			natTable.Delete(lockKey)
			cond.Broadcast()
		}()

		pCtx := icontext.NewPacketConnContext(metadata)
		//proxy, rule, err := resolveMetadata(pCtx, metadata)
		//if err != nil {
		//	log.Warnln("[UDP] Parse metadata failed: %s", err.Error())
		//	return
		//}
		proxy := proxies["GLOBAL"]
		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
		defer cancel()
		rawPc, err := proxy.ListenPacketContext(ctx, metadata.Pure())
		if err != nil {
			return
		}
		pCtx.InjectPacketConn(rawPc)
		pc := statistic.NewUDPTracker(rawPc, statistic.DefaultManager, metadata, nil)

		log.Infoln(
			"[UDP] %s --> %s",
			metadata.SourceAddress(),
			metadata.RemoteAddress(),
		)

		oAddr, _ := netip.AddrFromSlice(metadata.DstIP)
		oAddr = oAddr.Unmap()
		go handleUDPToLocal(packet.UDPPacket, pc, key, oAddr, fAddr)

		natTable.Set(key, pc)
		handle()
	}()
}

func handleTCPConn(connCtx C.ConnContext) {
	defer connCtx.Conn().Close()

	metadata := connCtx.Metadata()
	//if !metadata.Valid() {
	//	log.Warnln("[Metadata] not valid: %#v", metadata)
	//	return
	//}
	//
	//if err := preHandleMetadata(metadata); err != nil {
	//	log.Debugln("[Metadata PreHandle] error: %s", err)
	//	return
	//}

	proxy := proxies["GLOBAL"]

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	remoteConn, err := proxy.DialContext(ctx, metadata.Pure())
	if err != nil {
		return
	}
	remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, nil)
	defer remoteConn.Close()

	log.Infoln(
		"[TCP] %s --> %s",
		metadata.SourceAddress(),
		metadata.RemoteAddress(),
	)
	handleSocket(connCtx, remoteConn)
}

func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, metadata *C.Metadata) error {
	addr := metadata.UDPAddr()
	if addr == nil {
		return errors.New("udp addr invalid")
	}

	if _, err := pc.WriteTo(packet.Data(), addr); err != nil {
		return err
	}
	// reset timeout
	pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func handleUDPToLocal(packet C.UDPPacket, pc net.PacketConn, key string, oAddr, fAddr netip.Addr) {
	buf := pool.Get(pool.UDPBufferSize)
	defer pool.Put(buf)
	defer natTable.Delete(key)
	defer pc.Close()

	for {
		pc.SetReadDeadline(time.Now().Add(udpTimeout))
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}

		fromUDPAddr := *from.(*net.UDPAddr)
		if fAddr.IsValid() {
			fromAddr, _ := netip.AddrFromSlice(fromUDPAddr.IP)
			fromAddr = fromAddr.Unmap()
			if oAddr == fromAddr {
				fromUDPAddr.IP = fAddr.AsSlice()
			}
		}

		_, err = packet.WriteBack(buf[:n], &fromUDPAddr)
		if err != nil {
			return
		}
	}
}

func handleSocket(ctx C.ConnContext, outbound net.Conn) {
	N.Relay(ctx.Conn(), outbound)
}
