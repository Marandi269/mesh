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
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	icontext "github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/listener"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel/statistic"
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

func main() {
	go DnsServe()
	fmt.Println("hello")
	ports := listener.Ports{
		MixedPort: 7451,
	}
	listener.SetAllowLan(true)
	listener.ReCreatePortsListeners(ports, tcpQueue, udpQueue)
	listener.PatchTunnel(nil, tcpQueue, udpQueue)
	mapping := map[string]any{}
	proxy, _ := adapter.ParseProxy(mapping)
	proxies["GLOBAL"] = proxy
	go process()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
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
