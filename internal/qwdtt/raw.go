package qwdtt

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const rawInterface = "wdttraw0"

// TURN can hide a relay close, but RAW clients send keepalives roughly every
// 15 seconds. Expire a session after two missed keepalives.
const rawIdleTimeout = 25 * time.Second

// rawRouter is deliberately independent from WireGuard.  The Android
// rawtun client sends IPv4 packets directly; the router's kernel then routes
// and masquerades them through the WAN.
type rawRouter struct {
	file      *os.File
	mu        sync.Mutex
	sessions  map[string][]*rawConn
	rr        map[string]int
	chunk     map[string]int
	logs      *LogBook
	traffic   *TrafficStats
	firstUp   uint32
	firstDown uint32
}

type rawConn struct {
	conn    net.Conn
	done    chan struct{}
	sendCh  chan []byte
	traffic *ProfileSession
	stats   *TrafficStats
	logs    *LogBook
}

var rawPacketPool = sync.Pool{New: func() any { return make([]byte, 2048) }}

func getRawPacket(size int) []byte {
	b := rawPacketPool.Get().([]byte)
	if cap(b) < size {
		return make([]byte, size)
	}
	return b[:size]
}

func putRawPacket(b []byte) {
	if cap(b) >= 1024 && cap(b) <= 4096 {
		rawPacketPool.Put(b[:cap(b)])
	}
}

type rawNetConn struct {
	pc   net.PacketConn
	addr net.Addr
}

func (c *rawNetConn) Read(p []byte) (int, error) {
	for {
		n, _, err := c.pc.ReadFrom(p)
		if err != nil {
			if _, ok := err.(net.Error); ok {
				return 0, err
			}
			continue
		}
		return n, nil
	}
}
func (c *rawNetConn) Write(p []byte) (int, error)        { return c.pc.WriteTo(p, c.addr) }
func (c *rawNetConn) Close() error                       { return c.pc.Close() }
func (c *rawNetConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *rawNetConn) RemoteAddr() net.Addr               { return c.addr }
func (c *rawNetConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *rawNetConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *rawNetConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }

func newRawRouter(ctx context.Context, runner CommandRunner, network, wan string, mtu int) (*rawRouter, error) {
	if runner == nil {
		return nil, fmt.Errorf("command runner is nil")
	}
	_, ipnet, err := net.ParseCIDR(network)
	if err != nil || ipnet.IP.To4() == nil {
		return nil, fmt.Errorf("invalid raw network %q", network)
	}
	// iptables normalizes a /16 such as 10.70.66.0/16 to 10.70.0.0/16.
	// Use the canonical network everywhere so the managed rule matches the
	// route that the kernel installs for wdttraw0.
	network = ipnet.String()
	// Remove any stale TUN left by a previous process before creating the
	// replacement. Flush the address first because some Keenetic builds keep
	// it around briefly while the device is being torn down.
	_ = runner.Run(ctx, "ip", "link", "set", "dev", rawInterface, "down")
	_ = runner.Run(ctx, "ip", "addr", "flush", "dev", rawInterface)
	_ = runner.Run(ctx, "ip", "link", "del", rawInterface)
	f, err := createRawTUN(rawInterface)
	if err != nil {
		return nil, fmt.Errorf("create raw TUN: %w", err)
	}
	gateway := rawGateway(network)
	commands := [][]string{
		{"addr", "replace", gateway + "/16", "dev", rawInterface},
		{"link", "set", "mtu", fmt.Sprint(mtu), "dev", rawInterface},
		{"link", "set", "dev", rawInterface, "up"},
	}
	for _, args := range commands {
		if err := runner.Run(ctx, "ip", args...); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("configure raw TUN: %w", err)
		}
	}
	if wan == "" {
		wan = "br0"
	}
	// RAW is a real routed interface. Enabling forwarding here is important
	// when RAW is enabled without the WireGuard listener or after NDMS rebuilt
	// the firewall.
	if err := runner.Run(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("enable ipv4 forwarding: %w", err)
	}
	// Keep the working transport rules from the last upstream commit. Profile
	// restrictions are handled separately; these rules only make routed RAW
	// traffic reach the WAN and return to the TUN.
	firewall := [][]string{
		{"-t", "nat", "-C", "POSTROUTING", "-s", network, "-o", wan, "-j", "MASQUERADE"},
		{"-C", "FORWARD", "-i", rawInterface, "-j", "ACCEPT"},
		{"-C", "FORWARD", "-o", rawInterface, "-j", "ACCEPT"},
		{"-C", "INPUT", "-i", rawInterface, "-j", "ACCEPT"},
	}
	for _, rule := range firewall {
		if err := runner.Run(ctx, "iptables", rule...); err == nil {
			continue
		}
		add := append([]string(nil), rule...)
		for i := range add {
			if add[i] == "-C" {
				add[i] = "-I"
				if i+1 < len(add) {
					add = append(add[:i+2], append([]string{"1"}, add[i+2:]...)...)
				}
				break
			}
		}
		if err := runner.Run(ctx, "iptables", add...); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("raw firewall: %w", err)
		}
	}
	if err := runner.Run(ctx, "iptables", "-t", "nat", "-C", "POSTROUTING", "-s", network, "-j", "MASQUERADE"); err != nil {
		if err := runner.Run(ctx, "iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", network, "-j", "MASQUERADE"); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("raw NAT: %w", err)
		}
	}
	for _, args := range [][]string{
		{"-t", "mangle", "-C", "FORWARD", "-s", network, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		{"-t", "mangle", "-C", "FORWARD", "-d", network, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
	} {
		if err := runner.Run(ctx, "iptables", args...); err != nil {
			add := append([]string(nil), args...)
			for i := range add {
				if add[i] == "-C" {
					add[i] = "-A"
					break
				}
			}
			_ = runner.Run(ctx, "iptables", add...)
		}
	}
	r := &rawRouter{file: f, sessions: make(map[string][]*rawConn), rr: make(map[string]int), chunk: make(map[string]int)}
	go r.downlink(ctx)
	return r, nil
}

func (r *rawRouter) close() { _ = r.file.Close() }

func (r *rawRouter) add(ip string, c net.Conn, traffic *ProfileSession) *rawConn {
	w := &rawConn{conn: c, done: make(chan struct{}), sendCh: make(chan []byte, 256), traffic: traffic, stats: r.traffic, logs: r.logs}
	r.mu.Lock()
	r.sessions[ip] = append(r.sessions[ip], w)
	r.mu.Unlock()
	go func() {
		for {
			select {
			case packet := <-w.sendCh:
				if packet == nil {
					return
				}
				if _, err := w.conn.Write(packet); err == nil {
					if w.stats != nil {
						w.stats.AddRX(len(packet))
					}
					if w.traffic != nil {
						w.traffic.AddRX(len(packet))
					}
				} else {
					if w.traffic != nil {
						w.traffic.Touch()
					}
					if w.logs != nil {
						w.logs.Add("WARN", "[RAW] downlink write failed: %v", err)
					}
				}
				putRawPacket(packet)
			case <-w.done:
				return
			}
		}
	}()
	return w
}

func (r *rawRouter) remove(ip string, w *rawConn) {
	r.mu.Lock()
	items := r.sessions[ip]
	for i, item := range items {
		if item == w {
			items = append(items[:i], items[i+1:]...)
			break
		}
	}
	if len(items) == 0 {
		delete(r.sessions, ip)
		delete(r.rr, ip)
		delete(r.chunk, ip)
	} else {
		r.sessions[ip] = items
		if r.rr[ip] >= len(items) {
			r.rr[ip] = 0
		}
	}
	r.mu.Unlock()
	close(w.done)
}

func (r *rawRouter) downlink(ctx context.Context) {
	buf := make([]byte, 2048)
	for {
		n, err := r.file.Read(buf)
		if err != nil {
			return
		}
		if n < 20 || buf[0]>>4 != 4 {
			continue
		}
		dst := net.IP(buf[16:20]).String()
		r.mu.Lock()
		items := r.sessions[dst]
		if len(items) > 0 {
			// Spread a short chunk across relay workers. This is the upstream
			// qWDTT behavior and lets one TCP flow use all TURN relays without
			// excessive packet reordering.
			if r.chunk[dst] <= 0 {
				r.chunk[dst] = 8
			}
			idx := r.rr[dst] % len(items)
			r.chunk[dst]--
			if r.chunk[dst] == 0 {
				r.rr[dst] = (idx + 1) % len(items)
			}
			item := items[idx]
			packet := getRawPacket(n)
			copy(packet, buf[:n])
			r.mu.Unlock()
			select {
			case item.sendCh <- packet:
			case <-item.done:
				putRawPacket(packet)
			default:
				// Never block TUN reading behind a slow relay. Dropping an
				// overloaded packet is preferable to adding seconds of latency.
				putRawPacket(packet)
			}
			if atomic.CompareAndSwapUint32(&r.firstDown, 0, 1) && r.logs != nil {
				r.logs.Add("INFO", "[RAW] first downlink packet routed to %s: %d bytes", dst, n)
			}
		} else {
			r.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func rawIP(network string, index int) string {
	base := net.ParseIP(rawGateway(network)).To4()
	value := int(base[2])*256 + int(base[3]) + 1 + index
	return fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], byte(value>>8), byte(value))
}

func rawGateway(network string) string {
	_, n, _ := net.ParseCIDR(network)
	base := n.IP.To4()
	return fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], byte(66), byte(1))
}

func (s Service) startRaw(ctx context.Context, profiles []ConnectionProfile, runner CommandRunner) (func(), error) {
	if s.Config.Server.RawPort <= 0 {
		return func() {}, nil
	}
	router, err := newRawRouter(ctx, runner, s.Config.Server.RawNetwork, s.Config.Routing.WAN, s.Config.Server.RawMTU)
	if err != nil {
		return nil, err
	}
	router.logs = s.Logs
	router.traffic = s.Traffic
	port := s.Config.Server.RawPort
	addr := net.JoinHostPort("0.0.0.0", fmt.Sprint(port))
	keys := make([]wrapIdentity, 0, len(profiles))
	byID := make(map[string]ConnectionProfile, len(profiles))
	for _, p := range profiles {
		key, e := DeriveWrapKey(s.Config.profilePassword(p))
		if e != nil {
			router.close()
			return nil, e
		}
		keys = append(keys, wrapIdentity{id: p.ID, key: key})
		byID[p.ID] = p
	}
	var listener *wrappedListener
	// During a runtime restart the previous RAW listener can still be
	// unwinding while the new transport is already being reconciled. Wait a
	// little for that socket to close instead of disabling RAW permanently.
	for attempt := 0; attempt < 20; attempt++ {
		listener, err = newWrappedListener(mustUDPAddr(addr), keys, s.Logs)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			router.close()
			return func() {}, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		router.close()
		return nil, err
	}
	s.Logs.Add("INFO", "RAW listener started on %s; WRAP profiles=%d", addr, len(keys))
	var closeOnce sync.Once
	cleanup := func() {
		closeOnce.Do(func() {
			_ = listener.Close()
			router.close()
		})
	}
	go func() {
		<-ctx.Done()
		cleanup()
	}()
	// The classifier is normally driven by the DTLS listener on a shared
	// port. For a separate -listen-raw port, drive it explicitly so rawCh
	// receives the classified endpoints.
	s.startSession(func() {
		for {
			pc, _, e := listener.Accept()
			if e != nil {
				return
			}
			_ = pc.Close()
		}
	})
	s.startSession(func() {
		for {
			pc, remote, first, e := listener.AcceptRaw()
			if e != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			s.Logs.Add("INFO", "[RAW %s] UDP endpoint accepted", remote)
			s.startSession(func() {
				c := &rawNetConn{pc: pc, addr: remote}
				defer c.Close()
				var err error
				first, err = readRawInitialCommand(c, first, remote, s.Logs)
				if err != nil {
					return
				}
				profileID := listener.selectedProfile(remote)
				profile, ok := byID[profileID]
				if !ok {
					s.Logs.Add("WARN", "[RAW %s] WRAP profile was not selected (id=%q)", remote, profileID)
					return
				}
				s.Logs.Add("INFO", "[RAW %s profile=%s] WRAP authenticated", remote, profile.ID)
				if err := s.handleRaw(ctx, c, router, profile, string(first)); err != nil {
					s.Logs.Add("WARN", "raw client %s: %v", remote, err)
				}
			})
		}
	})
	return cleanup, nil
}

func mustUDPAddr(addr string) *net.UDPAddr { a, _ := net.ResolveUDPAddr("udp", addr); return a }

func (l *wrappedListener) selectedProfile(addr net.Addr) string { return l.ProfileID(addr) }

func (s Service) startRawOnListener(ctx context.Context, profiles []ConnectionProfile, listener *wrappedListener, runner CommandRunner) error {
	router, err := newRawRouter(ctx, runner, s.Config.Server.RawNetwork, s.Config.Routing.WAN, s.Config.Server.RawMTU)
	if err != nil {
		return err
	}
	router.logs = s.Logs
	router.traffic = s.Traffic
	byID := make(map[string]ConnectionProfile, len(profiles))
	for _, profile := range profiles {
		byID[profile.ID] = profile
	}
	go func() {
		<-ctx.Done()
		router.close()
	}()
	s.startSession(func() {
		for {
			pc, remote, first, err := listener.AcceptRaw()
			if err != nil {
				return
			}
			s.Logs.Add("INFO", "[RAW %s] shared-port endpoint accepted", remote)
			s.startSession(func() {
				c := &rawNetConn{pc: pc, addr: remote}
				defer c.Close()
				var err error
				first, err = readRawInitialCommand(c, first, remote, s.Logs)
				if err != nil {
					return
				}
				profileID := listener.selectedProfile(remote)
				profile, ok := byID[profileID]
				if !ok {
					s.Logs.Add("WARN", "[RAW %s] shared-port profile was not selected (id=%q)", remote, profileID)
					return
				}
				s.Logs.Add("INFO", "[RAW %s profile=%s] WRAP authenticated", remote, profile.ID)
				if err := s.handleRaw(ctx, c, router, profile, string(first)); err != nil {
					s.Logs.Add("WARN", "raw client %s: %v", remote, err)
				}
			})
		}
	})
	return nil
}

// readRawInitialCommand skips the variable-length RTP keepalives that a
// client worker may send before its AUTH/GETCONF_RAW command. A worker can
// produce more than one keepalive while TURN is being established, so one
// extra Read is not sufficient here.
func readRawInitialCommand(c net.Conn, first []byte, remote net.Addr, logs *LogBook) ([]byte, error) {
	buf := make([]byte, 2048)
	for len(first) > 0 && first[0] == 0xff {
		_ = c.SetReadDeadline(time.Now().Add(45 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			logs.Add("WARN", "[RAW %s] waiting for initial command failed: %v", remote, err)
			return nil, err
		}
		first = append(first[:0], buf[:n]...)
	}
	_ = c.SetReadDeadline(time.Time{})
	return first, nil
}

func (s Service) handleRaw(ctx context.Context, c net.Conn, router *rawRouter, profile ConnectionProfile, first string) error {
	prefix := "GETCONF_RAW:"
	if strings.HasPrefix(first, "AUTH:") {
		prefix = "AUTH:"
	}
	if !strings.HasPrefix(first, prefix) {
		return fmt.Errorf("unexpected initial command")
	}
	parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(first, prefix)), "|")
	if len(parts) < 2 || parts[0] == "" || parts[1] != s.Config.profilePassword(profile) {
		_, _ = c.Write([]byte("DENIED:wrong_password"))
		return fmt.Errorf("wrong password")
	}
	profileTraffic := s.ProfileTraffic.ConnectMode(profile.ID, "RAW")
	defer s.ProfileTraffic.Disconnect(profileTraffic)
	profileTraffic.Touch()
	// RAW uses the same stable-per-profile addressing model as WireGuard.
	// The netfilter script can therefore install restrictions before any
	// client connects and does not need a runtime firewall reconciler.
	ip := profile.RawIP
	if strings.HasPrefix(first, "GETCONF_RAW:") {
		_, _ = c.Write([]byte(fmt.Sprintf("RAWCONF:%s|%s|%d", ip, s.clientDNS(), s.Config.Server.RawMTU)))
	}
	s.Logs.Add("INFO", "[RAW profile=%s device=%s] assigned %s", profile.ID, parts[0], ip)
	w := router.add(ip, c, profileTraffic)
	defer func() {
		router.remove(ip, w)
	}()
	buf := make([]byte, 2048)
	lastActivity := time.Now()
	for {
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Since(lastActivity) <= rawIdleTimeout {
					continue
				}
			}
			return err
		}
		lastActivity = time.Now()
		if n > 0 {
			// Keepalive frames prove that the RAW session is still alive but
			// must not be written to the TUN device.
			if profileTraffic != nil {
				profileTraffic.Touch()
			}
			// Raw-клиент держит TURN/WRAP-сессию кадрами 0xFF размером
			// 25–44 байта. Это не IP-пакеты и их нельзя писать в TUN.
			if buf[0] == 0xFF {
				continue
			}
			if strings.HasPrefix(string(buf[:n]), "DISCONNECT_RAW:") {
				return nil
			}
			if _, err = router.file.Write(buf[:n]); err != nil {
				return err
			}
			if router.traffic != nil {
				router.traffic.AddTX(n)
			}
			if atomic.CompareAndSwapUint32(&router.firstUp, 0, 1) {
				s.Logs.Add("INFO", "[RAW profile=%s] first uplink IP packet: %d bytes", profile.ID, n)
			}
			profileTraffic.AddTX(n)
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}

func profileIndex(profiles []ConnectionProfile, id string) int {
	for i, p := range profiles {
		if p.ID == id {
			return i
		}
	}
	return 0
}
