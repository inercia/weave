package main

import (
	"flag"
	"fmt"
	"github.com/miekg/dns"
	. "github.com/weaveworks/weave/common"
	"github.com/weaveworks/weave/common/updater"
	weavedns "github.com/weaveworks/weave/nameserver"
	weavenet "github.com/weaveworks/weave/net"
	"net"
	"os"
)

var version = "(unreleased version)"

func main() {
	var (
		justVersion     bool
		ifaceName       string
		apiPath         string
		domain          string
		fallback        string
		dnsPort         int
		httpPort        int
		wait            int
		timeout         int
		udpbuf          int
		refreshInterval int
		relevantTime    int
		cacheLen        int
		cacheDisabled   bool
		watch           bool
		debug           bool
		err             error
	)

	flag.BoolVar(&justVersion, "version", false, "print version and exit")
	flag.StringVar(&ifaceName, "iface", "", "name of interface to use for multicast")
	flag.StringVar(&apiPath, "api", "unix:///var/run/docker.sock", "path to Docker API socket")
	flag.StringVar(&domain, "domain", weavedns.DefaultLocalDomain, "local domain (ie, 'weave.local.')")
	flag.IntVar(&wait, "wait", 0, "number of seconds to wait for interface to be created and come up")
	flag.IntVar(&dnsPort, "dnsport", weavedns.DefaultServerPort, "port to listen to DNS requests")
	flag.IntVar(&httpPort, "httpport", 6785, "port to listen to HTTP requests")
	flag.IntVar(&cacheLen, "cache", weavedns.DefaultCacheLen, "cache length")
	flag.BoolVar(&watch, "watch", true, "watch the docker socket for container events")
	flag.BoolVar(&debug, "debug", false, "output debugging info to stderr")
	// advanced options
	flag.StringVar(&fallback, "fallback", "", "force a fallback (ie, '8.8.8.8:53') (instead of /etc/resolv.conf values)")
	flag.IntVar(&refreshInterval, "refresh", weavedns.DefaultRefreshInterval, "refresh interval (in secs) for local names (0=disable)")
	flag.IntVar(&relevantTime, "relevant", weavedns.DefaultRelevantTime, "life time for info in the absence of queries (in secs)")
	flag.IntVar(&udpbuf, "udpbuf", weavedns.DefaultUDPBuflen, "UDP buffer length")
	flag.IntVar(&timeout, "timeout", weavedns.DefaultTimeout, "timeout for resolutions (in millisecs)")
	flag.BoolVar(&cacheDisabled, "no-cache", false, "disable the cache")

	flag.Parse()

	if justVersion {
		fmt.Printf("weave DNS %s\n", version)
		os.Exit(0)
	}

	InitDefaultLogging(debug)
	Info.Printf("[main] WeaveDNS version %s\n", version) // first thing in log: the version

	var iface *net.Interface
	if ifaceName != "" {
		var err error
		Info.Println("Waiting for interface", ifaceName, "to come up")
		iface, err = weavenet.EnsureInterface(ifaceName, wait)
		if err != nil {
			Error.Fatal(err)
		} else {
			Info.Println("Interface", ifaceName, "is up")
		}
	}

	zoneConfig := weavedns.ZoneConfig{
		Domain:          domain,
		Iface:           iface,
		RefreshInterval: refreshInterval,
		RelevantTime:    relevantTime,
	}
	zone, err := weavedns.NewZoneDb(zoneConfig)
	if err != nil {
		Error.Fatal("[main] Unable to initialize the Zone database", err)
	}
	err = zone.Start()
	if err != nil {
		Error.Fatal("[main] Unable to start the Zone database", err)
	}
	defer zone.Stop()

	if watch {
		err := updater.Start(apiPath, zone)
		if err != nil {
			Error.Fatal("[main] Unable to start watcher", err)
		}
	}

	srvConfig := weavedns.DNSServerConfig{
		Zone:          zone,
		Port:          dnsPort,
		CacheLen:      cacheLen,
		Timeout:       timeout,
		UDPBufLen:     udpbuf,
		CacheDisabled: cacheDisabled,
	}

	if len(fallback) > 0 {
		fallbackHost, fallbackPort, err := net.SplitHostPort(fallback)
		if err != nil {
			Error.Fatal("[main] Could not parse fallback host and port", err)
		}
		srvConfig.UpstreamCfg = &dns.ClientConfig{Servers: []string{fallbackHost}, Port: fallbackPort}
		Debug.Printf("[main] DNS fallback at %s:%s", fallbackHost, fallbackPort)
	}

	srv, err := weavedns.NewDNSServer(srvConfig)
	if err != nil {
		Error.Fatal("[main] Failed to initialize the WeaveDNS server", err)
	}

	InitDefaultSignalsHandler([]SignalsStopper{zone, srv})

	go weavedns.ListenHTTP(version, srv, domain, zone, httpPort)
	err = srv.Start()
	if err != nil {
		Error.Fatal("[main] Failed to start the WeaveDNS server: ", err)
	}
}
