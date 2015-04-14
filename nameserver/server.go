package nameserver

import (
	"bytes"
	"fmt"
	"github.com/benbjohnson/clock"
	"github.com/miekg/dns"
	. "github.com/weaveworks/weave/common"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	DefaultServerPort = 53                 // The default server port
	DefaultCLICfgFile = "/etc/resolv.conf" // default "resolv.conf" file to try to load
	DefaultUDPBuflen  = 4096               // bigger than the default 512
	DefaultCacheLen   = 8192               // default cache capacity
	DefaultTimeout    = 500                // default timeout for DNS resolutions (in milliseconds)
)

type DNSServerConfig struct {
	// The zone
	Zone Zone
	// (Optional) client config file for resolving upstream servers
	UpstreamCfgFile string
	// (Optional) DNS client config for the fallback server(s)
	UpstreamCfg *dns.ClientConfig
	// (Optional) port number (for TCP and UDP)
	Port int
	// (Optional) cache size
	CacheLen int
	// (Optional) disable the cache
	CacheDisabled bool
	// (Optional) timeout for DNS queries
	Timeout int
	// (Optional) UDP buffer length
	UDPBufLen int
	// (Optional) force a specific cache
	Cache ZoneCache
	// (Optional) TTL for negative results in the local domain
	CacheNegLocalTTL int
	// (Optional) for a specific clock provider
	Clock clock.Clock
	// (Optional) Listening socket read timeout (in milliseconds)
	ListenReadTimeout int
}

type dnsProtocol uint8

const (
	protUDP dnsProtocol = iota // UDP protocol
	protTCP dnsProtocol = iota // TCP protocol
)

func (proto dnsProtocol) String() string {
	switch proto {
	case protUDP:
		return "UDP"
	case protTCP:
		return "TCP"
	}
	return "unknown"
}

// get a new dns.Client for a protocol
func (proto dnsProtocol) GetNewClient(bufsize int, timeout time.Duration) *dns.Client {
	switch proto {
	case protTCP:
		return &dns.Client{Net: "tcp", ReadTimeout: timeout}
	case protUDP:
		return &dns.Client{Net: "udp", ReadTimeout: timeout, UDPSize: uint16(bufsize)}
	}
	return nil
}
// a DNS server
type DNSServer struct {
	Zone       Zone
	Upstream   *dns.ClientConfig
	Domain     string // the local domain
	ListenAddr string // the address the server is listening at

	udpSrv        *dns.Server
	tcpSrv        *dns.Server
	pc            net.PacketConn
	lst           net.Listener
	cache         ZoneCache
	cacheDisabled bool
	negLocalTTL   int
	timeout       time.Duration
	readTimeout   time.Duration
	udpBuf        int
	listenersWg   *sync.WaitGroup
	clock         clock.Clock
}

// Creates a new DNS server
func NewDNSServer(config DNSServerConfig) (s *DNSServer, err error) {
	s = &DNSServer{
		Zone:       config.Zone,
		Domain:     DefaultLocalDomain,
		ListenAddr: fmt.Sprintf(":%d", config.Port),

		listenersWg:   new(sync.WaitGroup),
		timeout:       time.Duration(config.Timeout) * time.Millisecond,
		readTimeout:   time.Duration(config.ListenReadTimeout) * time.Millisecond,
		cacheDisabled: false,
		negLocalTTL:   negLocalTTL,
		clock:         config.Clock,
	}

	// check some basic parameters are valid
	if s.Zone == nil {
		return nil, fmt.Errorf("No valid Zone provided in server initialization")
	}
	if len(s.Domain) == 0 {
		return nil, fmt.Errorf("No valid Domain provided in server initialization")
	}
	if s.clock == nil {
		s.clock = clock.New()
	}

	// fill empty parameters with defaults...
	if config.UpstreamCfg != nil {
		s.Upstream = config.UpstreamCfg
	} else {
		cfgFile := DefaultCLICfgFile
		if len(config.UpstreamCfgFile) > 0 {
			cfgFile = config.UpstreamCfgFile
		}
		if s.Upstream, err = dns.ClientConfigFromFile(cfgFile); err != nil {
			return nil, err
		}
	}
	if config.Timeout > 0 {
		s.timeout = time.Duration(config.Timeout) * time.Millisecond
	}
	if config.UDPBufLen > 0 {
		s.udpBuf = config.UDPBufLen
	}
	if config.CacheNegLocalTTL > 0 {
		s.negLocalTTL = config.CacheNegLocalTTL
	}
	if config.CacheDisabled {
		s.cacheDisabled = true
	}
	if !s.cacheDisabled {
		if config.Cache != nil {
			s.cache = config.Cache
		} else {
			cacheLen := DefaultCacheLen
			if config.CacheLen > 0 {
				cacheLen = config.CacheLen
			}
			if s.cache, err = NewCache(cacheLen, s.clock); err != nil {
				return
			}
		}
	}

	return
}

// Start the DNS server
func (s *DNSServer) Start() error {
	Info.Printf("[dns] Upstream server(s): %+v", s.Upstream)
	if s.cacheDisabled {
		Info.Printf("[dns] Cache: disabled")
	} else {
		Info.Printf("[dns] Cache: %d entries", s.cache.Capacity())
	}

	// create two DNS request multiplexerers, depending on the protocol used by clients
	// (we use the same protocol for asking upstream servers)
	mux := func(proto dnsProtocol) *dns.ServeMux {
		m := dns.NewServeMux()
		m.HandleFunc(s.Zone.Domain(), s.queryHandler(proto))
		m.HandleFunc(RDNSDomain, s.rdnsHandler(proto))
		m.HandleFunc(".", s.notUsHandler(proto))
		return m
	}

	pc, err := net.ListenPacket("udp", s.ListenAddr)
	if err != nil {
		return err
	}
	s.pc = pc

	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		return err
	}
	s.ListenAddr = fmt.Sprintf(":%s", port)
	s.udpSrv = &dns.Server{PacketConn: s.pc, Handler: mux(protUDP), ReadTimeout: s.readTimeout}

	// Bind the TCP socket at the same port, aborting otherwise
	l, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		s.Stop()
		return err
	}
	s.lst = l
	s.tcpSrv = &dns.Server{Listener: l, Handler: mux(protTCP), ReadTimeout: s.readTimeout}

	s.listenersWg.Add(2)

	go func() {
		defer s.listenersWg.Done()

		Info.Printf("[dns] Listening for DNS on %s (UDP)", s.ListenAddr)
		err := s.udpSrv.ActivateAndServe()
		CheckFatal(err)
		Debug.Printf("[dns] DNS UDP server exiting...")
	}()

	go func() {
		defer s.listenersWg.Done()

		Info.Printf("[dns] Listening for DNS on %s (TCP)", s.ListenAddr)
		err := s.tcpSrv.ActivateAndServe()
		CheckFatal(err)
		Debug.Printf("[dns] DNS TCP server exiting...")
	}()

	// Waiting for all goroutines to finish (otherwise they die as main routine dies)
	s.listenersWg.Wait()

	Info.Printf("[dns] Server exiting...")
	return nil
}

// Return status string
func (s *DNSServer) Status() string {
	var buf bytes.Buffer
	fmt.Fprintln(&buf, "Listen address", s.ListenAddr)
	fmt.Fprintln(&buf, "Fallback DNS config", s.Upstream)
	return buf.String()
}

// Perform a graceful shutdown
func (s *DNSServer) Stop() error {
	// Stop the listeners/handlers
	if s.tcpSrv != nil {
		if err := s.tcpSrv.Shutdown(); err != nil {
			return err
		}
		s.lst.Close()
		s.tcpSrv = nil
	}
	if s.udpSrv != nil {
		if err := s.udpSrv.Shutdown(); err != nil {
			return err
		}
		s.pc.Close()
		s.udpSrv = nil
	}
	s.listenersWg.Wait()
	return nil
}

func (s *DNSServer) queryHandler(proto dnsProtocol) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		maxLen := getMaxReplyLen(r, proto)
		Debug.Printf("[dns] Query: %+v", q)

		if !s.cacheDisabled {
			reply, err := s.cache.Get(r, maxLen)
			if err != nil {
				Debug.Printf("[dns msgid %d] Error from cache: %s", r.MsgHdr.Id, err)
				w.WriteMsg(makeDNSFailResponse(r))
				return
			}
			if reply != nil {
				Debug.Printf("[dns msgid %d] Returning reply from cache: %s/%d answers",
					r.MsgHdr.Id, dns.RcodeToString[reply.MsgHdr.Rcode], len(reply.Answer))
				w.WriteMsg(reply)
				return
			}
		}

		// catch unsupported queries
		if q.Qtype != dns.TypeA {
			Debug.Printf("[dns msgid %d] Unsuported query type %s", r.MsgHdr.Id, dns.TypeToString[q.Qtype])
			m := makeDNSNotImplResponse(r)
			if !s.cacheDisabled {
				s.cache.Put(r, m, s.negLocalTTL, 0)
				s.Zone.ObserveName(q.Name, func() { s.cache.Remove(&q) })
			}
			w.WriteMsg(m)
			return
		}

		if ips, err := s.Zone.DomainLookupName(q.Name); err == nil {
			m := makeAddressReply(r, &q, ips)
			m.Authoritative = true

			if !s.cacheDisabled {
				Debug.Printf("[dns msgid %d] Caching and sending response for %s-query for \"%s\": %s [code:%s]",
					m.MsgHdr.Id, dns.TypeToString[q.Qtype], q.Name, ips, dns.RcodeToString[m.Rcode])
				s.cache.Put(r, m, nullTTL, 0)
				// any change in the zone database for this name will lead to this cache entry being removed...
				s.Zone.ObserveName(q.Name, func() { s.cache.Remove(&q) })
			} else {
				Debug.Printf("[dns msgid %d] Sending response for %s-query for \"%s\": %s [code:%s]",
					m.MsgHdr.Id, dns.TypeToString[q.Qtype], q.Name, ips, dns.RcodeToString[m.Rcode])
			}
			w.WriteMsg(m)
			return
		}

		Info.Printf("[dns msgid %d] No results for %s-query '%s'", r.MsgHdr.Id, dns.TypeToString[q.Qtype], q.Name)
		if !s.cacheDisabled {
			Info.Printf("[dns msgid %d] caching no-local", r.MsgHdr.Id)
			s.cache.Put(r, nil, s.negLocalTTL, CacheNoLocalReplies)
			s.Zone.ObserveName(q.Name, func() { s.cache.Remove(&q) })
		}
		w.WriteMsg(makeDNSFailResponse(r))
	}
}

func (s *DNSServer) rdnsHandler(proto dnsProtocol) dns.HandlerFunc {
	fallback := s.notUsHandler(proto)
	return func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		maxLen := getMaxReplyLen(r, proto)
		Debug.Printf("[dns] Reverse query: %+v", q)

		if !s.cacheDisabled {
			reply, err := s.cache.Get(r, maxLen)
			if err != nil {
				Debug.Printf("[dns msgid %d] Error from cache: %s", r.MsgHdr.Id, err)
				w.WriteMsg(makeDNSFailResponse(r))
				return
			}
			if reply != nil {
				Debug.Printf("[dns msgid %d] Returning reply from cache: %s/%d answers",
					r.MsgHdr.Id, dns.RcodeToString[reply.MsgHdr.Rcode], len(reply.Answer))
				w.WriteMsg(reply)
				return
			}
		}

		// catch unsupported queries
		if q.Qtype != dns.TypePTR {
			Warning.Printf("[dns msgid %d] Unexpected reverse query type %s: %+v",
				r.MsgHdr.Id, dns.TypeToString[q.Qtype], q)
			m := makeDNSNotImplResponse(r)
			if !s.cacheDisabled {
				s.cache.Put(r, m, s.negLocalTTL, 0)
				s.Zone.ObserveInaddr(q.Name, func() { s.cache.Remove(&q) })
			}
			w.WriteMsg(m)
			return
		}

		if names, err := s.Zone.DomainLookupInaddr(q.Name); err == nil {
			m := makePTRReply(r, &q, names)
			m.Authoritative = true

			if !s.cacheDisabled {
				Debug.Printf("[dns msgid %d] Caching and sending response: %s-query/%s [code:%s]",
					m.MsgHdr.Id, dns.TypeToString[q.Qtype], q.Name, names, dns.RcodeToString[m.Rcode])
				s.cache.Put(r, m, nullTTL, 0)
				// any change in the Zone database for this IP will lead to this cache entry being removed...
				// TODO: this closure results in unnecessary `Remove`s and some wasted mem... but we can live with that.
				s.Zone.ObserveInaddr(q.Name, func() { s.cache.Remove(&q) })
			} else {
				Debug.Printf("[dns msgid %d] Sending response: %s-query/%s [code:%s]",
					m.MsgHdr.Id, dns.TypeToString[q.Qtype], q.Name, names, dns.RcodeToString[m.Rcode])
			}
			w.WriteMsg(m)
			return
		}

		Info.Printf("[dns msgid %d] No results for %s-query about '%s' -> sending to fallback server",
			r.MsgHdr.Id, dns.TypeToString[q.Qtype], q.Name)
		if !s.cacheDisabled {
			Info.Printf("[dns msgid %d] caching no-local", r.MsgHdr.Id)
			s.cache.Put(r, nil, s.negLocalTTL, CacheNoLocalReplies)
			s.Zone.ObserveInaddr(q.Name, func() { s.cache.Remove(&q) })
		}
		fallback(w, r)
	}
}

// When we receive a request for a name outside of our '.weave.local.'
// domain, ask the configured DNS server as a fallback.
func (s *DNSServer) notUsHandler(proto dnsProtocol) dns.HandlerFunc {
	dnsClient := proto.GetNewClient(DefaultUDPBuflen, s.timeout)

	return func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]

		// announce our max payload size as the max payload our client supports
		maxLen := getMaxReplyLen(r, proto)
		rcopy := r
		rcopy.SetEdns0(uint16(maxLen), false)

		Debug.Printf("[dns msgid %d] Fallback query: %+v [%s, max:%d bytes]", rcopy.MsgHdr.Id, q, proto, maxLen)
		for _, server := range s.Upstream.Servers {
			reply, _, err := dnsClient.Exchange(rcopy, fmt.Sprintf("%s:%s", server, s.Upstream.Port))
			if err != nil {
				Debug.Printf("[dns msgid %d] Network error trying %s (%s)",
					r.MsgHdr.Id, server, err)
				continue
			}
			if reply != nil && reply.Rcode != dns.RcodeSuccess {
				Debug.Printf("[dns msgid %d] Failure reported by %s for query %s",
					r.MsgHdr.Id, server, q.Name)
				continue
			}
			Debug.Printf("[dns msgid %d] Given answer by %s for query %s",
				r.MsgHdr.Id, server, q.Name)
			w.WriteMsg(reply)
			return
		}
		Warning.Printf("[dns msgid %d] Failed lookup for external name %s", r.MsgHdr.Id, q.Name)
		w.WriteMsg(makeDNSFailResponse(r))
	}
}

// Get the listen port
func (s *DNSServer) GetPort() (int, error) {
	_, portS, err := net.SplitHostPort(s.ListenAddr)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(portS)
}
