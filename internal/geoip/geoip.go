// Package geoip resolves IPv4 addresses to ISO 3166-1 alpha-2 country codes
// from a local range table. Lookups never leave the host, so watching who
// knocks does not tell a third party who is probing this machine.
package geoip

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"os"
	"slices"
)

// entry is one closed range of IPv4 addresses assigned to a single country.
// The code is an index into DB.codes so a lookup returns an interned string
// instead of allocating on every call.
type entry struct {
	start, end uint32
	code       uint16
}

// DB is a sorted range table. A nil *DB is usable and reports every address as
// unknown, which is what the daemon holds when no database was configured.
type DB struct {
	entries []entry
	codes   []string
}

// Load reads "range_start,range_end,country_code" rows with numeric IPv4
// bounds, the format published by ip-location-db.
func Load(path string) (*DB, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open geoip database: %w", err)
	}
	defer file.Close()

	db := &DB{}
	known := make(map[[2]byte]uint16)
	scanner := bufio.NewScanner(file)
	sorted := true

	for line := 1; scanner.Scan(); line++ {
		row := bytes.TrimSpace(scanner.Bytes())
		if len(row) == 0 {
			continue
		}
		start, end, code, err := parseRow(row)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		index, seen := known[code]
		if !seen {
			if len(db.codes) > math.MaxUint16 {
				return nil, fmt.Errorf("%s: too many distinct country codes", path)
			}
			index = uint16(len(db.codes))
			db.codes = append(db.codes, string(code[:]))
			known[code] = index
		}
		if n := len(db.entries); n > 0 && start < db.entries[n-1].start {
			sorted = false
		}
		db.entries = append(db.entries, entry{start: start, end: end, code: index})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read geoip database: %w", err)
	}
	if !sorted {
		slices.SortFunc(db.entries, func(a, b entry) int { return cmp.Compare(a.start, b.start) })
	}
	return db, nil
}

// Country reports the ISO code for ip. It returns an empty string when no
// database is loaded, the address is not IPv4, or no range covers it.
func (d *DB) Country(ip string) string {
	if d == nil || len(d.entries) == 0 {
		return ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return ""
	}
	octets := addr.As4()
	target := binary.BigEndian.Uint32(octets[:])

	index, found := slices.BinarySearchFunc(d.entries, target, func(e entry, target uint32) int {
		switch {
		case e.end < target:
			return -1
		case e.start > target:
			return 1
		default:
			return 0
		}
	})
	if !found {
		return ""
	}
	return d.codes[d.entries[index].code]
}

// Len reports how many ranges were loaded, for start-up logging.
func (d *DB) Len() int {
	if d == nil {
		return 0
	}
	return len(d.entries)
}

func parseRow(row []byte) (start, end uint32, code [2]byte, err error) {
	firstComma := bytes.IndexByte(row, ',')
	if firstComma < 0 {
		return 0, 0, code, fmt.Errorf("missing comma in %q", row)
	}
	rest := row[firstComma+1:]
	secondComma := bytes.IndexByte(rest, ',')
	if secondComma < 0 {
		return 0, 0, code, fmt.Errorf("missing second comma in %q", row)
	}

	start, ok := parseUint32(row[:firstComma])
	if !ok {
		return 0, 0, code, fmt.Errorf("bad range start in %q", row)
	}
	end, ok = parseUint32(rest[:secondComma])
	if !ok {
		return 0, 0, code, fmt.Errorf("bad range end in %q", row)
	}
	if end < start {
		return 0, 0, code, fmt.Errorf("reversed range in %q", row)
	}

	letters := rest[secondComma+1:]
	if len(letters) != 2 {
		return 0, 0, code, fmt.Errorf("country code is not two letters in %q", row)
	}
	return start, end, [2]byte{letters[0], letters[1]}, nil
}

func parseUint32(field []byte) (uint32, bool) {
	if len(field) == 0 || len(field) > 10 {
		return 0, false
	}
	var value uint64
	for _, c := range field {
		if c < '0' || c > '9' {
			return 0, false
		}
		value = value*10 + uint64(c-'0')
	}
	if value > math.MaxUint32 {
		return 0, false
	}
	return uint32(value), true
}
