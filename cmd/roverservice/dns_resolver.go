package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

type dnsResolveOptions struct {
	Upstreams []string
	Fallbacks []string
	Bootstrap []string
	Proxy     string
	ProxyAddr string
	ProxyUser string
	ProxyPass string
	Timeout   time.Duration
	RootCAs   *x509.CertPool
}

type dnsStringList []string

func (l *dnsStringList) UnmarshalJSON(data []byte) error {
	var values []string
	if err := json.Unmarshal(data, &values); err == nil {
		*l = cleanStringList(values)
		return nil
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*l = headerList(value)
	return nil
}

func mergeStringLists(lists ...dnsStringList) []string {
	var merged []string
	for _, list := range lists {
		merged = append(merged, []string(list)...)
	}
	return cleanStringList(merged)
}

type dnsUpstreamInfo struct {
	Raw      string
	Network  string
	Host     string
	Port     string
	Path     string
	Server   string
	DialAddr string
}

type dnsResult struct {
	msg    *dns.Msg
	server string
	err    error
}

func resolveDNSJSONWithOptions(parent context.Context, req dnsQueryRequest, opts dnsResolveOptions) (dnsQueryResponse, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return dnsQueryResponse{}, errors.New("name is required")
	}
	qtypeName := strings.ToUpper(strings.TrimSpace(req.Type))
	if qtypeName == "" {
		qtypeName = "A"
	}
	qtype, ok := dns.StringToType[qtypeName]
	if !ok {
		return dnsQueryResponse{}, fmt.Errorf("unsupported query type %s", qtypeName)
	}
	msg, server, err := resolveDNSMessage(parent, name, qtype, opts)
	if err != nil {
		return dnsQueryResponse{}, err
	}
	return dnsResponseFromMsg(msg, server), nil
}

func resolveDNSWireQuery(parent context.Context, payload []byte, opts dnsResolveOptions) ([]byte, error) {
	req := new(dns.Msg)
	if err := req.Unpack(payload); err != nil {
		return nil, fmt.Errorf("unpack query: %w", err)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 8 * time.Second
	}
	msg, _, err := exchangeDNSMessage(parent, req, opts)
	if err != nil {
		return nil, err
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack response: %w", err)
	}
	return packed, nil
}

func resolveDNSMessage(parent context.Context, name string, qtype uint16, opts dnsResolveOptions) (*dns.Msg, string, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	req.RecursionDesired = true
	return exchangeDNSMessage(parent, req, opts)
}

func exchangeDNSMessage(parent context.Context, req *dns.Msg, opts dnsResolveOptions) (*dns.Msg, string, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if len(cleanStringList(opts.Upstreams)) == 0 {
		return exchangeSystemDNS(parent, req, opts.Timeout)
	}
	ctx, cancel := context.WithTimeout(parent, opts.Timeout)
	defer cancel()

	resp, server, err := raceDNSUpstreams(ctx, req, cleanStringList(opts.Upstreams), opts)
	if err == nil {
		return resp, server, nil
	}
	if len(cleanStringList(opts.Fallbacks)) == 0 {
		return nil, "", err
	}
	resp, server, fallbackErr := raceDNSUpstreams(ctx, req, cleanStringList(opts.Fallbacks), opts)
	if fallbackErr == nil {
		return resp, server, nil
	}
	return nil, "", fmt.Errorf("upstreams failed: %v; fallback failed: %w", err, fallbackErr)
}

func raceDNSUpstreams(ctx context.Context, req *dns.Msg, upstreams []string, opts dnsResolveOptions) (*dns.Msg, string, error) {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dnsResult, len(upstreams))
	for _, upstream := range upstreams {
		go func(server string) {
			msg := req.Copy()
			resp, err := exchangeSingleDNS(childCtx, msg, server, opts)
			select {
			case results <- dnsResult{msg: resp, server: server, err: err}:
			case <-childCtx.Done():
			}
		}(upstream)
	}
	var lastErr error
	for i := 0; i < len(upstreams); i++ {
		select {
		case res := <-results:
			if res.err == nil && res.msg != nil && res.msg.Rcode == dns.RcodeSuccess {
				cancel()
				return res.msg, res.server, nil
			}
			if res.err != nil {
				lastErr = res.err
			} else {
				lastErr = fmt.Errorf("%s returned %s", res.server, dns.RcodeToString[res.msg.Rcode])
			}
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("all upstreams failed")
	}
	return nil, "", lastErr
}

func exchangeSingleDNS(ctx context.Context, req *dns.Msg, upstream string, opts dnsResolveOptions) (*dns.Msg, error) {
	info, err := parseDNSUpstream(upstream)
	if err != nil {
		return nil, err
	}
	if opts.Proxy == "" {
		if err := resolveDNSUpstreamDialAddr(ctx, &info, opts); err != nil {
			return nil, err
		}
	}
	switch info.Network {
	case "https":
		return exchangeDoH(ctx, req, info, opts)
	case "tls":
		return exchangeTLS(ctx, req, info, opts)
	case "tcp":
		return exchangeStreamDNS(ctx, req, "tcp", info, opts)
	default:
		if strings.EqualFold(opts.Proxy, "socks5") {
			return exchangeStreamDNS(ctx, req, "tcp", info, opts)
		}
		client := &dns.Client{Net: "udp", Timeout: opts.Timeout}
		resp, _, err := client.ExchangeContext(ctx, req, info.DialAddr)
		return resp, err
	}
}

func exchangeSystemDNS(parent context.Context, req *dns.Msg, timeout time.Duration) (*dns.Msg, string, error) {
	if len(req.Question) == 0 {
		return nil, "", errors.New("empty DNS question")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	question := req.Question[0]
	resolver := net.DefaultResolver
	response := new(dns.Msg)
	response.SetReply(req)

	switch question.Qtype {
	case dns.TypeA, dns.TypeAAAA:
		network := "ip"
		if question.Qtype == dns.TypeA {
			network = "ip4"
		} else {
			network = "ip6"
		}
		ips, err := resolver.LookupIP(ctx, network, strings.TrimSuffix(question.Name, "."))
		if err != nil {
			return nil, "", err
		}
		for _, ip := range ips {
			if question.Qtype == dns.TypeA {
				response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: ip})
			} else {
				response.Answer = append(response.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: ip})
			}
		}
	case dns.TypeCNAME:
		cname, err := resolver.LookupCNAME(ctx, strings.TrimSuffix(question.Name, "."))
		if err != nil {
			return nil, "", err
		}
		response.Answer = append(response.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: dns.Fqdn(cname)})
	case dns.TypeMX:
		records, err := resolver.LookupMX(ctx, strings.TrimSuffix(question.Name, "."))
		if err != nil {
			return nil, "", err
		}
		for _, record := range records {
			response.Answer = append(response.Answer, &dns.MX{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET}, Preference: record.Pref, Mx: dns.Fqdn(record.Host)})
		}
	case dns.TypeTXT:
		records, err := resolver.LookupTXT(ctx, strings.TrimSuffix(question.Name, "."))
		if err != nil {
			return nil, "", err
		}
		for _, record := range records {
			response.Answer = append(response.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{record}})
		}
	default:
		return nil, "", fmt.Errorf("unsupported query type %s", dns.TypeToString[question.Qtype])
	}
	return response, "system", nil
}

func exchangeDoH(ctx context.Context, req *dns.Msg, info dnsUpstreamInfo, opts dnsResolveOptions) (*dns.Msg, error) {
	packed, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack query: %w", err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: info.Host, RootCAs: opts.RootCAs}}
	if info.DialAddr != "" && opts.Proxy == "" {
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: opts.Timeout}).DialContext(ctx, network, info.DialAddr)
		}
	}
	if strings.EqualFold(opts.Proxy, "socks5") {
		dialer, err := socks5ContextDialer(opts)
		if err != nil {
			return nil, err
		}
		transport.DialContext = dialer.DialContext
	}
	client := &http.Client{Transport: transport, Timeout: opts.Timeout}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, info.Raw, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d", httpResp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 65535))
	if err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		return nil, err
	}
	return resp, nil
}

func exchangeTLS(ctx context.Context, req *dns.Msg, info dnsUpstreamInfo, opts dnsResolveOptions) (*dns.Msg, error) {
	conn, err := dialDNSContext(ctx, "tcp", info.DialAddr, opts)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: info.Host, RootCAs: opts.RootCAs})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	defer tlsConn.Close()
	dnsConn := &dns.Conn{Conn: tlsConn}
	if err := dnsConn.WriteMsg(req); err != nil {
		return nil, err
	}
	return dnsConn.ReadMsg()
}

func exchangeStreamDNS(ctx context.Context, req *dns.Msg, network string, info dnsUpstreamInfo, opts dnsResolveOptions) (*dns.Msg, error) {
	if strings.EqualFold(opts.Proxy, "socks5") || network == "tcp" {
		conn, err := dialDNSContext(ctx, "tcp", info.DialAddr, opts)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		dnsConn := &dns.Conn{Conn: conn}
		if err := dnsConn.WriteMsg(req); err != nil {
			return nil, err
		}
		return dnsConn.ReadMsg()
	}
	client := &dns.Client{Net: network, Timeout: opts.Timeout}
	resp, _, err := client.ExchangeContext(ctx, req, info.DialAddr)
	return resp, err
}

func dialDNSContext(ctx context.Context, network, address string, opts dnsResolveOptions) (net.Conn, error) {
	if strings.EqualFold(opts.Proxy, "socks5") {
		dialer, err := socks5ContextDialer(opts)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, address)
	}
	return (&net.Dialer{Timeout: opts.Timeout}).DialContext(ctx, network, address)
}

func socks5ContextDialer(opts dnsResolveOptions) (proxy.ContextDialer, error) {
	if strings.TrimSpace(opts.ProxyAddr) == "" {
		return nil, errors.New("proxy_addr is required for socks5 DNS queries")
	}
	var auth *proxy.Auth
	if opts.ProxyUser != "" || opts.ProxyPass != "" {
		auth = &proxy.Auth{User: opts.ProxyUser, Password: opts.ProxyPass}
	}
	dialer, err := proxy.SOCKS5("tcp", opts.ProxyAddr, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("SOCKS5 dialer does not support context")
	}
	return contextDialer, nil
}

func parseDNSUpstream(raw string) (dnsUpstreamInfo, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return dnsUpstreamInfo{}, errors.New("empty DNS upstream")
	}
	info := dnsUpstreamInfo{Raw: raw, Network: "udp"}
	switch {
	case strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://"):
		parsed, err := url.Parse(raw)
		if err != nil {
			return dnsUpstreamInfo{}, err
		}
		info.Network = "https"
		info.Host = parsed.Hostname()
		info.Port = parsed.Port()
		if info.Port == "" {
			if parsed.Scheme == "http" {
				info.Port = "80"
			} else {
				info.Port = "443"
			}
		}
		info.Path = parsed.EscapedPath()
		if info.Path == "" {
			info.Path = "/dns-query"
		}
	case strings.HasPrefix(raw, "tls://"):
		info.Network = "tls"
		info.Host, info.Port = splitDNSHostPort(strings.TrimPrefix(raw, "tls://"), "853")
	case strings.HasPrefix(raw, "tcp://"):
		info.Network = "tcp"
		info.Host, info.Port = splitDNSHostPort(strings.TrimPrefix(raw, "tcp://"), "53")
	case strings.HasPrefix(raw, "udp://"):
		info.Network = "udp"
		info.Host, info.Port = splitDNSHostPort(strings.TrimPrefix(raw, "udp://"), "53")
	default:
		info.Host, info.Port = splitDNSHostPort(raw, "53")
	}
	if info.Host == "" {
		return dnsUpstreamInfo{}, fmt.Errorf("invalid DNS upstream %q", raw)
	}
	info.Server = net.JoinHostPort(info.Host, info.Port)
	info.DialAddr = info.Server
	return info, nil
}

func resolveDNSUpstreamDialAddr(ctx context.Context, info *dnsUpstreamInfo, opts dnsResolveOptions) error {
	if net.ParseIP(info.Host) != nil || len(cleanStringList(opts.Bootstrap)) == 0 {
		info.DialAddr = net.JoinHostPort(info.Host, info.Port)
		return nil
	}
	ip, err := bootstrapResolveHost(ctx, info.Host, opts)
	if err != nil {
		return err
	}
	info.DialAddr = net.JoinHostPort(ip, info.Port)
	return nil
}

func bootstrapResolveHost(ctx context.Context, host string, opts dnsResolveOptions) (string, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(host), dns.TypeA)
	req.RecursionDesired = true
	for _, bootstrap := range cleanStringList(opts.Bootstrap) {
		localOpts := opts
		localOpts.Bootstrap = nil
		resp, err := exchangeSingleDNS(ctx, req.Copy(), bootstrap, localOpts)
		if err == nil {
			for _, answer := range resp.Answer {
				if record, ok := answer.(*dns.A); ok {
					return record.A.String(), nil
				}
			}
		}
	}
	return "", fmt.Errorf("bootstrap resolve failed for %s", host)
}

func dnsResponseFromMsg(msg *dns.Msg, server string) dnsQueryResponse {
	out := dnsQueryResponse{RCode: dns.RcodeToString[msg.Rcode], Server: server}
	for _, rr := range msg.Answer {
		header := rr.Header()
		answer := dnsQueryAnswer{Name: header.Name, Type: dns.TypeToString[header.Rrtype], TTL: int(header.Ttl)}
		switch record := rr.(type) {
		case *dns.A:
			answer.Value = record.A.String()
		case *dns.AAAA:
			answer.Value = record.AAAA.String()
		case *dns.CNAME:
			answer.Value = record.Target
		case *dns.MX:
			answer.Value = fmt.Sprintf("%d %s", record.Preference, record.Mx)
		case *dns.TXT:
			answer.Value = strings.Join(record.Txt, "")
		default:
			answer.Value = strings.TrimSpace(rr.String())
		}
		out.Answers = append(out.Answers, answer)
	}
	return out
}

func splitDNSHostPort(value, defaultPort string) (string, string) {
	host, port, err := net.SplitHostPort(value)
	if err == nil {
		return host, port
	}
	return strings.Trim(value, "[]"), defaultPort
}

func headerList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return cleanStringList(strings.Split(value, ","))
}

func cleanStringList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

var bootstrapCache sync.Map

func clearDNSBootstrapCacheForTest() {
	bootstrapCache.Range(func(key, _ any) bool {
		bootstrapCache.Delete(key)
		return true
	})
}
