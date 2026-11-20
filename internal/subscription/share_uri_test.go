package subscription

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func mustShareURI(t *testing.T, raw string) string {
	t.Helper()
	uri, ok := ShareURI(json.RawMessage(raw))
	if !ok {
		t.Fatalf("ShareURI(%s) reported unsupported", raw)
	}
	return uri
}

func parseOneShareURI(t *testing.T, uri string) map[string]any {
	t.Helper()
	nodes, err := ParseGeneralSubscription([]byte(uri))
	if err != nil {
		t.Fatalf("parse %q: %v", uri, err)
	}
	if len(nodes) != 1 {
		t.Fatalf("parse %q: got %d nodes, want 1", uri, len(nodes))
	}
	var options map[string]any
	if err := json.Unmarshal(nodes[0].RawOptions, &options); err != nil {
		t.Fatalf("unmarshal %q options: %v", uri, err)
	}
	return options
}

func TestShareURIShadowsocksRoundTrip(t *testing.T) {
	uri := mustShareURI(t, `{
		"type":"shadowsocks","tag":"ss-sg","server":"192.0.2.10","server_port":8388,
		"method":"aes-128-gcm","password":"secret",
		"plugin":"obfs-local","plugin_opts":"obfs=http;obfs-host=example.com"
	}`)
	if !strings.HasPrefix(uri, "ss://") {
		t.Fatalf("uri = %q, want ss:// prefix", uri)
	}
	options := parseOneShareURI(t, uri)
	assertField(t, options, "type", "shadowsocks")
	assertField(t, options, "server", "192.0.2.10")
	assertField(t, options, "method", "aes-128-gcm")
	assertField(t, options, "password", "secret")
	assertField(t, options, "tag", "ss-sg")
	assertField(t, options, "plugin", "obfs-local")
	if opts := getString(options, "plugin_opts"); !strings.Contains(opts, "obfs=http") {
		t.Fatalf("plugin_opts = %q, want obfs=http", opts)
	}
}

func TestShareURIVMessRoundTrip(t *testing.T) {
	uri := mustShareURI(t, `{
		"type":"vmess","tag":"vm-jp","server":"192.0.2.11","server_port":443,
		"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"auto","alter_id":0,
		"tls":{"enabled":true,"server_name":"cdn.example.com","alpn":["h2","http/1.1"]},
		"transport":{"type":"ws","path":"/ray","headers":{"Host":"cdn.example.com"}}
	}`)
	if !strings.HasPrefix(uri, "vmess://") {
		t.Fatalf("uri = %q, want vmess:// prefix", uri)
	}
	options := parseOneShareURI(t, uri)
	assertField(t, options, "type", "vmess")
	assertField(t, options, "server", "192.0.2.11")
	assertField(t, options, "uuid", "b831381d-6324-4d53-ad4f-8cda48b30811")
	assertField(t, options, "tag", "vm-jp")

	tls, ok := getMap(options, "tls")
	if !ok {
		t.Fatal("missing tls after round-trip")
	}
	if enabled, _ := getBool(tls, "enabled"); !enabled {
		t.Fatal("tls.enabled = false after round-trip")
	}
	assertField(t, tls, "server_name", "cdn.example.com")

	transport, ok := getMap(options, "transport")
	if !ok {
		t.Fatal("missing transport after round-trip")
	}
	assertField(t, transport, "type", "ws")
	assertField(t, transport, "path", "/ray")
	headers, ok := getMap(transport, "headers")
	if !ok {
		t.Fatal("missing ws headers after round-trip")
	}
	assertField(t, headers, "Host", "cdn.example.com")
}

func TestShareURIVLESSRealityRoundTrip(t *testing.T) {
	uri := mustShareURI(t, `{
		"type":"vless","tag":"vl-us","server":"192.0.2.12","server_port":443,
		"uuid":"2f4d2f9c-1c1e-4a0f-9b0f-1f0a2b3c4d5e","flow":"xtls-rprx-vision",
		"tls":{"enabled":true,"server_name":"www.example.com",
			"reality":{"enabled":true,"public_key":"PbKeyExample","short_id":"abcd1234"},
			"utls":{"enabled":true,"fingerprint":"chrome"}},
		"transport":{"type":"grpc","service_name":"grpcsvc"}
	}`)
	options := parseOneShareURI(t, uri)
	assertField(t, options, "type", "vless")
	assertField(t, options, "server", "192.0.2.12")
	assertField(t, options, "uuid", "2f4d2f9c-1c1e-4a0f-9b0f-1f0a2b3c4d5e")
	assertField(t, options, "flow", "xtls-rprx-vision")

	tls, ok := getMap(options, "tls")
	if !ok {
		t.Fatal("missing tls after round-trip")
	}
	assertField(t, tls, "server_name", "www.example.com")
	reality, ok := getMap(tls, "reality")
	if !ok {
		t.Fatal("missing tls.reality after round-trip")
	}
	assertField(t, reality, "public_key", "PbKeyExample")
	assertField(t, reality, "short_id", "abcd1234")

	transport, ok := getMap(options, "transport")
	if !ok {
		t.Fatal("missing transport after round-trip")
	}
	assertField(t, transport, "type", "grpc")
	assertField(t, transport, "service_name", "grpcsvc")
}

func TestShareURITrojanRoundTrip(t *testing.T) {
	uri := mustShareURI(t, `{
		"type":"trojan","tag":"tj-hk","server":"192.0.2.13","server_port":8443,
		"password":"p@ss:word",
		"tls":{"enabled":true,"server_name":"trojan.example.com","insecure":true},
		"transport":{"type":"ws","path":"/tj","headers":{"Host":"trojan.example.com"}}
	}`)
	options := parseOneShareURI(t, uri)
	assertField(t, options, "type", "trojan")
	assertField(t, options, "server", "192.0.2.13")
	assertField(t, options, "password", "p@ss:word")
	assertField(t, options, "tag", "tj-hk")

	tls, ok := getMap(options, "tls")
	if !ok {
		t.Fatal("missing tls after round-trip")
	}
	assertField(t, tls, "server_name", "trojan.example.com")
	transport, ok := getMap(options, "transport")
	if !ok {
		t.Fatal("missing transport after round-trip")
	}
	assertField(t, transport, "type", "ws")
	assertField(t, transport, "path", "/tj")
}

func TestShareURIHysteria2RoundTrip(t *testing.T) {
	uri := mustShareURI(t, `{
		"type":"hysteria2","tag":"hy2-sg","server":"192.0.2.14","server_port":443,
		"password":"hy2-pass","server_ports":["20000-30000"],"up_mbps":100,"down_mbps":500,
		"tls":{"enabled":true,"server_name":"hy2.example.com","alpn":["h3"]},
		"obfs":{"type":"salamander","password":"obfs-pass"}
	}`)
	options := parseOneShareURI(t, uri)
	assertField(t, options, "type", "hysteria2")
	assertField(t, options, "server", "192.0.2.14")
	assertField(t, options, "password", "hy2-pass")
	assertField(t, options, "tag", "hy2-sg")
	if up, _ := getUint(options, "up_mbps"); up != 100 {
		t.Fatalf("up_mbps = %d, want 100", up)
	}
	if down, _ := getUint(options, "down_mbps"); down != 500 {
		t.Fatalf("down_mbps = %d, want 500", down)
	}
	obfs, ok := getMap(options, "obfs")
	if !ok {
		t.Fatal("missing obfs after round-trip")
	}
	assertField(t, obfs, "type", "salamander")
	assertField(t, obfs, "password", "obfs-pass")
}

func TestShareURITUIC(t *testing.T) {
	uri := mustShareURI(t, `{
		"type":"tuic","tag":"tuic-us","server":"192.0.2.15","server_port":443,
		"uuid":"3a5b1c2d-0000-1111-2222-333344445555","password":"tuic-pass",
		"congestion_control":"bbr","udp_relay_mode":"native",
		"tls":{"enabled":true,"server_name":"tuic.example.com","alpn":["h3"]}
	}`)
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse tuic uri: %v", err)
	}
	if parsed.Scheme != "tuic" {
		t.Fatalf("scheme = %q, want tuic", parsed.Scheme)
	}
	if parsed.User.Username() != "3a5b1c2d-0000-1111-2222-333344445555" {
		t.Fatalf("uuid = %q", parsed.User.Username())
	}
	if password, _ := parsed.User.Password(); password != "tuic-pass" {
		t.Fatalf("password = %q", password)
	}
	if parsed.Host != "192.0.2.15:443" {
		t.Fatalf("host = %q", parsed.Host)
	}
	query := parsed.Query()
	if query.Get("sni") != "tuic.example.com" ||
		query.Get("congestion_control") != "bbr" ||
		query.Get("udp_relay_mode") != "native" ||
		query.Get("alpn") != "h3" {
		t.Fatalf("unexpected tuic query: %v", query)
	}
	if parsed.Fragment != "tuic-us" {
		t.Fatalf("fragment = %q, want tuic-us", parsed.Fragment)
	}
}

func TestShareURIUnsupported(t *testing.T) {
	for _, raw := range []string{
		`{"type":"http","server":"192.0.2.1","server_port":8080}`,
		`{"type":"socks","server":"192.0.2.1","server_port":1080}`,
		`{"type":"wireguard","server":"192.0.2.1","server_port":51820}`,
		`{"type":"anytls","server":"192.0.2.1","server_port":443}`,
		`{"type":"shadowsocks","server":"","server_port":0,"method":"aes-128-gcm","password":"x"}`,
		`not-json`,
	} {
		if uri, ok := ShareURI(json.RawMessage(raw)); ok {
			t.Fatalf("ShareURI(%s) = %q, want unsupported", raw, uri)
		}
	}
}

func TestShareURIDeterministic(t *testing.T) {
	raw := json.RawMessage(`{
		"type":"vless","tag":"det","server":"192.0.2.16","server_port":443,
		"uuid":"2f4d2f9c-1c1e-4a0f-9b0f-1f0a2b3c4d5e",
		"tls":{"enabled":true,"server_name":"example.com"}
	}`)
	first := mustShareURI(t, string(raw))
	second := mustShareURI(t, string(raw))
	if first != second {
		t.Fatalf("ShareURI is not deterministic:\nfirst  = %q\nsecond = %q", first, second)
	}
}

func assertField(t *testing.T, options map[string]any, key, want string) {
	t.Helper()
	if got := getString(options, key); got != want {
		t.Fatalf("%s = %q, want %q", key, got, want)
	}
}
