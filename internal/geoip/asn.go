package geoip

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

// ASNResult is the autonomous-system classification of one egress IP.
type ASNResult struct {
	Number    uint32
	Org       string
	IsHosting bool
}

// ASNReader resolves egress-IP AS numbers from a local GeoLite2-ASN database.
// A nil or closed reader degrades to zero-value results, so a missing or
// unreadable database disables the feature without failing the service.
type ASNReader interface {
	Lookup(ip netip.Addr) ASNResult
	Close() error
}

type asnNoOpReader struct{}

func (asnNoOpReader) Lookup(netip.Addr) ASNResult { return ASNResult{} }
func (asnNoOpReader) Close() error                { return nil }

type asnMMDBReader struct {
	reader *maxminddb.Reader
}

type mmdbASNRecord struct {
	AutonomousSystemNumber uint32 `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrg    string `maxminddb:"autonomous_system_organization"`
}

func (m *asnMMDBReader) Lookup(ip netip.Addr) ASNResult {
	if m == nil || m.reader == nil || !ip.IsValid() {
		return ASNResult{}
	}
	ip = ip.Unmap()
	var record mmdbASNRecord
	if err := m.reader.Lookup(net.IP(ip.AsSlice()), &record); err != nil || record.AutonomousSystemNumber == 0 {
		return ASNResult{}
	}
	return ASNResult{
		Number:    record.AutonomousSystemNumber,
		Org:       record.AutonomousSystemOrg,
		IsHosting: IsHostingASN(record.AutonomousSystemNumber),
	}
}

func (m *asnMMDBReader) Close() error {
	if m == nil || m.reader == nil {
		return nil
	}
	return m.reader.Close()
}

// ASNMMDBOpen opens a GeoLite2-ASN (or ASN-compatible) mmdb database.
func ASNMMDBOpen(path string) (ASNReader, error) {
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &asnMMDBReader{reader: reader}, nil
}

// OpenASNReader opens the ASN database at path when it exists. A missing file
// yields the no-op reader (feature disabled); any other error fails so a
// corrupt database surfaces at boot instead of silently degrading.
func OpenASNReader(path string) (ASNReader, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return asnNoOpReader{}, nil
	}
	_, statErr := os.Stat(trimmed)
	if os.IsNotExist(statErr) {
		return asnNoOpReader{}, nil
	}
	if statErr != nil {
		return nil, statErr
	}
	return ASNMMDBOpen(trimmed)
}

// hostingASNs lists the AS numbers of the large cloud/hosting providers most
// commonly flagged for bulk account registrations. The list is intentionally
// not exhaustive: it targets the providers observed in production bans and
// can be extended via the RESIN_HOSTING_ASN environment variable.
var hostingASNs = map[uint32]struct{}{
	16509: {}, // Amazon AWS
	14618: {}, // Amazon AWS ec2
	396982: {}, // Google Cloud
	8075: {},  // Microsoft Azure
	14061: {}, // DigitalOcean
	63949: {}, // Linode/Akamai
	20473: {}, // Choopa/Vultr
	16276: {}, // OVH
	24940: {}, // Hetzner
	51167: {}, // Contabo
	36352: {}, // ColocationCrossing
	60781: {}, // LeaseWeb
	9009: {},  // M247
	31898: {}, // Oracle Cloud
	21859: {}, // Zenlayer/GTHost adjacent
	55286: {}, // B2 Net Solutions / server.in
	53667: {}, // FranTech Solutions
	45102: {}, // Alibaba Cloud US
	37963: {}, // Alibaba Cloud
	132203: {}, // Tencent Cloud
}

// ExtendHostingASNs adds the comma-separated AS numbers to the hosting set.
// Invalid entries are reported so configuration mistakes surface at boot.
func ExtendHostingASNs(raw string) error {
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		num, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return err
		}
		hostingASNs[uint32(num)] = struct{}{}
	}
	return nil
}

// IsHostingASN reports whether the AS number is in the hosting set.
func IsHostingASN(num uint32) bool {
	_, ok := hostingASNs[num]
	return ok
}
