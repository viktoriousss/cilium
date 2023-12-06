package bitlpm

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCIDRTrie(t *testing.T) {

	trie := NewCIDRTrie[string]()

	prefixes := map[string]netip.Prefix{
		"0":    netip.MustParsePrefix("0.0.0.0/0"),
		"1":    netip.MustParsePrefix("1.0.0.0/8"),
		"2a":   netip.MustParsePrefix("1.1.0.0/16"),
		"2b":   netip.MustParsePrefix("1.2.0.0/16"),
		"3a":   netip.MustParsePrefix("1.1.1.0/24"),
		"3b":   netip.MustParsePrefix("1.2.1.0/24"),
		"4a":   netip.MustParsePrefix("1.1.1.0/25"),
		"4b":   netip.MustParsePrefix("1.1.1.128/25"),
		"last": netip.MustParsePrefix("1.1.1.129/32"),
	}

	// These are prefixes that have a direct longer match
	overridden := []string{
		"3a", // because 1.1.1.0/24 -> 1.1.1.0/25
	}

	for name, prefix := range prefixes {
		trie.Upsert(prefix, name)
	}

loop:
	for name := range prefixes {
		for _, over := range overridden {
			if name == over {
				continue loop
			}
		}
		have := trie.Lookup(prefixes[name])
		if have != name {
			t.Errorf("Lookup(%s) returned %s want %s", prefixes[name].String(), have, name)
		}
	}

	// Search should return the complete path to the prefix
	// will look up 1.1.1.128/25.
	wantPath := []string{
		"0",    // 0.0.0.0/0
		"1",    // 1.0.0.0/8
		"2a",   // 1.1.0.0/16
		"3a",   // 1.1.1.0/24
		"4b",   // 1.1.1.128/25
		"last", // 1.1.1.129/32
	}

	havePath := []string{}
	trie.Path(prefixes["last"], func(k netip.Prefix, v string) bool {
		wantK := prefixes[v]
		if wantK != k {
			t.Errorf("Search(%s) returned an unexpected key-value pair: k %s v %s", prefixes["last"], k.String(), v)
		}
		havePath = append(havePath, v)
		return true
	})
	t.Log(havePath)
	assert.Equal(t, wantPath, havePath)

	for _, tc := range []struct {
		k string
		v string
	}{
		{
			"1.1.1.130/32",
			"4b",
		},
		{
			"1.1.1.1/32",
			"4a",
		},
		{
			"1.24.0.0/32",
			"1",
		},
		{
			"24.24.24.24/32",
			"0",
		},
	} {
		assert.Equal(t, tc.v, trie.Lookup(netip.MustParsePrefix(tc.k)))
	}

}

func TestBitValueAt(t *testing.T) {
	for i, tc := range []struct {
		v    netip.Prefix
		i    uint
		want uint8
	}{
		// note: prefix length does not matter
		{
			v:    netip.MustParsePrefix("00ff:ffff::/128"),
			i:    0,
			want: 0,
		}, {
			v:    netip.MustParsePrefix("00ff:ffff::/128"),
			i:    7,
			want: 0,
		}, {
			v:    netip.MustParsePrefix("00ff:ffff::/128"),
			i:    8,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:ffff::/128"),
			i:    9,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    16,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    17,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    18,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    19,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    20,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    21,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    22,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    23,
			want: 0,
		},
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			have := cidrKey(tc.v).BitValueAt(tc.i)
			if have != tc.want {
				t.Errorf("Prefix %s index %d got bit %d, want %d", tc.v.String(), tc.i, have, tc.want)
			}
		})
	}
}

func TestCommonPrefix(t *testing.T) {
	for i, tc := range []struct {
		v1   netip.Prefix
		v2   netip.Prefix
		want uint
	}{
		{
			v1:   netip.MustParsePrefix("00ff::/128"),
			v2:   netip.MustParsePrefix("00fe::/128"),
			want: 15,
		},
		{
			v1:   netip.MustParsePrefix("f0ff::/128"),
			v2:   netip.MustParsePrefix("00fe::/128"),
			want: 0,
		},
		{
			v1:   netip.MustParsePrefix("ffff::/128"),
			v2:   netip.MustParsePrefix("ff7f::/128"),
			want: 8,
		},
		{
			v1:   netip.MustParsePrefix("ffff::/128"),
			v2:   netip.MustParsePrefix("fe7f::/128"),
			want: 7,
		},
		{
			v1:   netip.MustParsePrefix("::/128"),
			v2:   netip.MustParsePrefix("::/128"),
			want: 128,
		}, {
			v1:   netip.MustParsePrefix("::/128"),
			v2:   netip.MustParsePrefix("::1/128"),
			want: 127,
		},
	} {

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			have := cidrKey(tc.v1).CommonPrefix(tc.v2)
			if have != tc.want {
				t.Errorf("p1 %v p2 %v got %d want %d", tc.v1, tc.v2, have, tc.want)
			}
		})
	}
}
