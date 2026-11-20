package subscription

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ShareURI converts a sing-box outbound options object (as stored in
// node.RawOptions) back into a standard share URI.
//
// Supported schemes: ss, vmess, vless, trojan, hysteria2, tuic. Outbound types
// without a supported share-URI form (http, socks, wireguard, anytls, ...)
// return false. The output round-trips through the URI-line parser above.
func ShareURI(rawOptions json.RawMessage) (string, bool) {
	var options map[string]any
	if err := json.Unmarshal(rawOptions, &options); err != nil {
		return "", false
	}
	switch strings.ToLower(strings.TrimSpace(getString(options, "type"))) {
	case "shadowsocks":
		return encodeShadowsocksURI(options)
	case "vmess":
		return encodeVMessURI(options)
	case "vless":
		return encodeVLESSURI(options)
	case "trojan":
		return encodeTrojanURI(options)
	case "hysteria2":
		return encodeHysteria2URI(options)
	case "tuic":
		return encodeTUICURI(options)
	default:
		return "", false
	}
}

type shareTLSConfig struct {
	enabled     bool
	serverName  string
	insecure    bool
	alpn        []string
	fingerprint string
	realityPub  string
	realitySID  string
}

func shareTLS(options map[string]any) shareTLSConfig {
	var cfg shareTLSConfig
	tls, ok := getMap(options, "tls")
	if !ok {
		return cfg
	}
	cfg.enabled, _ = getBool(tls, "enabled")
	cfg.serverName = strings.TrimSpace(getString(tls, "server_name", "serverName"))
	cfg.insecure, _ = getBool(tls, "insecure")
	cfg.alpn = getStringList(tls, "alpn")
	if utls, ok := getMap(tls, "utls"); ok {
		cfg.fingerprint = strings.TrimSpace(getString(utls, "fingerprint"))
	}
	if reality, ok := getMap(tls, "reality"); ok {
		cfg.realityPub = strings.TrimSpace(getString(reality, "public_key", "publicKey"))
		cfg.realitySID = strings.TrimSpace(getString(reality, "short_id", "shortId"))
	}
	return cfg
}

type shareTransportConfig struct {
	kind        string
	path        string
	serviceName string
	host        string
}

func shareTransport(options map[string]any) shareTransportConfig {
	var cfg shareTransportConfig
	transport, ok := getMap(options, "transport")
	if !ok {
		return cfg
	}
	cfg.kind = strings.ToLower(strings.TrimSpace(getString(transport, "type")))
	cfg.path = strings.TrimSpace(getString(transport, "path"))
	cfg.serviceName = strings.TrimSpace(getString(transport, "service_name", "serviceName"))
	if hosts := getStringList(transport, "host"); len(hosts) > 0 {
		cfg.host = strings.Join(hosts, ",")
	}
	if headers, ok := getMap(transport, "headers"); ok {
		if host := strings.TrimSpace(getString(headers, "Host", "host")); host != "" {
			cfg.host = host
		}
	}
	return cfg
}

func shareEndpoint(options map[string]any) (server string, port uint64, tag string, ok bool) {
	server = strings.TrimSpace(getString(options, "server"))
	if server == "" {
		return "", 0, "", false
	}
	port, ok = getUint(options, "server_port", "port")
	if !ok || port == 0 || port > 65535 {
		return "", 0, "", false
	}
	tag = strings.TrimSpace(getString(options, "tag"))
	return server, port, tag, true
}

func buildShareURI(scheme string, user *url.Userinfo, server string, port uint64, tag string, query url.Values) string {
	u := url.URL{
		Scheme:   scheme,
		User:     user,
		Host:     net.JoinHostPort(server, strconv.FormatUint(port, 10)),
		RawQuery: query.Encode(),
		Fragment: tag,
	}
	return u.String()
}

// applyTransportQuery writes V2Ray transport parameters in the URI-line
// dialect accepted by parseVlessURI/parseTrojanURI.
func applyTransportQuery(query url.Values, transport shareTransportConfig) {
	if transport.kind == "" || transport.kind == "tcp" {
		return
	}
	query.Set("type", transport.kind)
	if transport.path != "" {
		query.Set("path", transport.path)
	}
	if transport.host != "" {
		query.Set("host", transport.host)
	}
	if transport.serviceName != "" {
		query.Set("serviceName", transport.serviceName)
		if transport.kind == "grpc" && transport.path == "" {
			query.Set("path", transport.serviceName)
		}
	}
}

func encodeShadowsocksURI(options map[string]any) (string, bool) {
	server, port, tag, ok := shareEndpoint(options)
	if !ok {
		return "", false
	}
	method := strings.TrimSpace(getString(options, "method"))
	password := getString(options, "password")
	if method == "" || password == "" {
		return "", false
	}
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
	query := url.Values{}
	if plugin := strings.TrimSpace(getString(options, "plugin")); plugin != "" {
		spec := plugin
		if opts := strings.TrimSpace(getString(options, "plugin_opts")); opts != "" {
			spec += ";" + opts
		}
		query.Set("plugin", spec)
	}
	u := url.URL{
		Scheme:   "ss",
		User:     url.User(userinfo),
		Host:     net.JoinHostPort(server, strconv.FormatUint(port, 10)),
		RawQuery: query.Encode(),
		Fragment: tag,
	}
	return u.String(), true
}

func encodeVMessURI(options map[string]any) (string, bool) {
	server, port, tag, ok := shareEndpoint(options)
	if !ok {
		return "", false
	}
	uuid := strings.TrimSpace(getString(options, "uuid"))
	if uuid == "" {
		return "", false
	}
	alterID, _ := getUint(options, "alter_id")
	security := strings.TrimSpace(getString(options, "security"))
	if security == "" {
		security = "auto"
	}
	tls := shareTLS(options)
	transport := shareTransport(options)

	network := "tcp"
	switch transport.kind {
	case "ws":
		network = "ws"
	case "grpc":
		network = "grpc"
	case "http", "h2":
		network = "h2"
	case "quic":
		network = "quic"
	case "httpupgrade":
		network = "httpupgrade"
	}

	payload := map[string]any{
		"v":    "2",
		"ps":   tag,
		"add":  server,
		"port": strconv.FormatUint(port, 10),
		"id":   uuid,
		"aid":  strconv.FormatUint(alterID, 10),
		"scy":  security,
		"net":  network,
		"type": "none",
	}
	switch network {
	case "ws", "h2":
		if transport.path != "" {
			payload["path"] = transport.path
		}
		if transport.host != "" {
			payload["host"] = transport.host
		}
	case "grpc":
		if transport.serviceName != "" {
			payload["path"] = transport.serviceName
		}
	}
	if tls.enabled {
		payload["tls"] = "tls"
	}
	if tls.serverName != "" {
		payload["sni"] = tls.serverName
	}
	if len(tls.alpn) > 0 {
		payload["alpn"] = strings.Join(tls.alpn, ",")
	}
	if tls.fingerprint != "" {
		payload["fp"] = tls.fingerprint
	}
	if tls.insecure {
		payload["allowInsecure"] = true
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", false
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(encoded), true
}

func encodeVLESSURI(options map[string]any) (string, bool) {
	server, port, tag, ok := shareEndpoint(options)
	if !ok {
		return "", false
	}
	uuid := strings.TrimSpace(getString(options, "uuid"))
	if uuid == "" {
		return "", false
	}
	tls := shareTLS(options)
	transport := shareTransport(options)

	query := url.Values{}
	query.Set("encryption", "none")
	if flow := strings.TrimSpace(getString(options, "flow")); flow != "" {
		query.Set("flow", flow)
	}
	if tls.enabled || tls.realityPub != "" || tls.realitySID != "" ||
		tls.serverName != "" || tls.insecure || len(tls.alpn) > 0 || tls.fingerprint != "" {
		security := "tls"
		if tls.realityPub != "" || tls.realitySID != "" {
			security = "reality"
			if tls.realityPub != "" {
				query.Set("pbk", tls.realityPub)
			}
			if tls.realitySID != "" {
				query.Set("sid", tls.realitySID)
			}
			if tls.fingerprint == "" {
				tls.fingerprint = "chrome"
			}
		}
		query.Set("security", security)
	}
	if tls.serverName != "" {
		query.Set("sni", tls.serverName)
	}
	if tls.insecure {
		query.Set("allowInsecure", "1")
	}
	if len(tls.alpn) > 0 {
		query.Set("alpn", strings.Join(tls.alpn, ","))
	}
	if tls.fingerprint != "" {
		query.Set("fp", tls.fingerprint)
	}
	applyTransportQuery(query, transport)
	return buildShareURI("vless", url.User(uuid), server, port, tag, query), true
}

func encodeTrojanURI(options map[string]any) (string, bool) {
	server, port, tag, ok := shareEndpoint(options)
	if !ok {
		return "", false
	}
	password := strings.TrimSpace(getString(options, "password"))
	if password == "" {
		return "", false
	}
	tls := shareTLS(options)
	transport := shareTransport(options)

	query := url.Values{}
	if tls.serverName != "" {
		query.Set("sni", tls.serverName)
	}
	if tls.insecure {
		query.Set("allowInsecure", "1")
	}
	if len(tls.alpn) > 0 {
		query.Set("alpn", strings.Join(tls.alpn, ","))
	}
	if tls.fingerprint != "" {
		query.Set("fp", tls.fingerprint)
	}
	applyTransportQuery(query, transport)
	return buildShareURI("trojan", url.User(password), server, port, tag, query), true
}

func encodeHysteria2URI(options map[string]any) (string, bool) {
	server, port, tag, ok := shareEndpoint(options)
	if !ok {
		return "", false
	}
	password := strings.TrimSpace(getString(options, "password"))
	if password == "" {
		return "", false
	}
	tls := shareTLS(options)

	query := url.Values{}
	if tls.serverName != "" {
		query.Set("sni", tls.serverName)
	}
	if tls.insecure {
		query.Set("insecure", "1")
	}
	if len(tls.alpn) > 0 {
		query.Set("alpn", strings.Join(tls.alpn, ","))
	}
	if obfs, ok := getMap(options, "obfs"); ok {
		if obfsType := strings.TrimSpace(getString(obfs, "type")); obfsType != "" {
			query.Set("obfs", obfsType)
			if obfsPassword := strings.TrimSpace(getString(obfs, "password")); obfsPassword != "" {
				query.Set("obfs-password", obfsPassword)
			}
		}
	}
	if ports := getStringList(options, "server_ports"); len(ports) > 0 {
		query.Set("ports", strings.Join(ports, ","))
	}
	if up, ok := getUint(options, "up_mbps"); ok && up > 0 {
		query.Set("upmbps", strconv.FormatUint(up, 10))
	}
	if down, ok := getUint(options, "down_mbps"); ok && down > 0 {
		query.Set("downmbps", strconv.FormatUint(down, 10))
	}
	if hop := strings.TrimSpace(getString(options, "hop_interval")); hop != "" {
		query.Set("hopInterval", hop)
	}
	return buildShareURI("hysteria2", url.User(password), server, port, tag, query), true
}

func encodeTUICURI(options map[string]any) (string, bool) {
	server, port, tag, ok := shareEndpoint(options)
	if !ok {
		return "", false
	}
	uuid := strings.TrimSpace(getString(options, "uuid"))
	if uuid == "" {
		return "", false
	}
	password := getString(options, "password")
	tls := shareTLS(options)

	query := url.Values{}
	if tls.serverName != "" {
		query.Set("sni", tls.serverName)
	}
	if tls.insecure {
		query.Set("allow_insecure", "1")
	}
	if len(tls.alpn) > 0 {
		query.Set("alpn", strings.Join(tls.alpn, ","))
	}
	if congestion := strings.TrimSpace(getString(options, "congestion_control")); congestion != "" {
		query.Set("congestion_control", congestion)
	}
	if mode := strings.TrimSpace(getString(options, "udp_relay_mode")); mode != "" {
		query.Set("udp_relay_mode", mode)
	}

	user := url.User(uuid)
	if password != "" {
		user = url.UserPassword(uuid, password)
	}
	return buildShareURI("tuic", user, server, port, tag, query), true
}
