// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
)

const (
	mapName = "tunnel_endpoint_map"

	// MaxEntries is the maximum entries in the tunnel endpoint map
	MaxEntries = 65536
)

var (
	mapInstance = bpf.NewMap(mapName,
		bpf.MapTypeHash,
		int(unsafe.Sizeof(tunnelKey{})),
		int(unsafe.Sizeof(tunnelEndpoint{})),
		MaxEntries, 0)
)

// Must be in sync with ENDPOINT_KEY_* in <bpf/lib/common.h>
const (
	tunnelKeyIPv4 uint8 = 1
	tunnelKeyIPv6 uint8 = 2
)

// Must be in sync with struct endpoint_key in <bpf/lib/common.h>
type tunnelKey struct {
	IP     types.IPv6
	Family uint8
	Pad1   uint8
	Pad2   uint16
}

func newTunnelKey(ip net.IP) tunnelKey {
	key := tunnelKey{}

	if ip4 := ip.To4(); ip4 != nil {
		key.Family = tunnelKeyIPv4
		copy(key.IP[:], ip4)
	} else {
		key.Family = tunnelKeyIPv6
		copy(key.IP[:], ip)
	}

	return key
}

func (k tunnelKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(&k) }
func (k tunnelKey) NewValue() bpf.MapValue    { return &tunnelEndpoint{} }

type tunnelEndpoint struct {
	IP types.IPv6
}

func (v tunnelEndpoint) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&v) }
func (v tunnelEndpoint) String() string              { return v.IP.String() }

// SetTunnelEndpoint adds/replaces a prefix => tunnel-endpoint mapping
func SetTunnelEndpoint(prefix net.IP, endpoint net.IP) error {
	key, val := newTunnelKey(prefix), tunnelEndpoint{}
	if ip4 := endpoint.To4(); ip4 != nil {
		copy(val.IP[:], ip4)
	} else {
		copy(val.IP[:], endpoint)
	}

	return mapInstance.Update(key, val)
}

// DeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func DeleteTunnelEndpoint(prefix net.IP) error {
	return mapInstance.Delete(newTunnelKey(prefix))
}

func dumpParser(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
	k, v := tunnelKey{}, tunnelEndpoint{}

	if err := binary.Read(bytes.NewBuffer(key), binary.LittleEndian, &k); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert key: %s\n", err)
	}

	if err := binary.Read(bytes.NewBuffer(value), binary.LittleEndian, &v); err != nil {
		return nil, nil, fmt.Errorf("Unable to convert key: %s\n", err)
	}

	return k, v, nil
}

func dumpCallback(key bpf.MapKey, value bpf.MapValue) {
	k, v := key.(tunnelKey), value.(tunnelEndpoint)
	switch k.Family {
	case tunnelKeyIPv4:
		prefix := net.IPv4(k.IP[0], k.IP[1], k.IP[2], k.IP[3])
		endpoint := net.IPv4(v.IP[0], v.IP[1], v.IP[2], v.IP[3])
		fmt.Printf("%-20s %s\n", prefix, endpoint)

	case tunnelKeyIPv6:
		// No special casting required, 16byte address will be detected as IPv6
		fmt.Printf("%-20s %s\n", k.IP, v.IP)

	default:
		fmt.Printf("%-20s %s (invalid family)\n", k.IP, k.IP)
	}
}

// DumpMap prints the content of the tunnel endpoint map to stdout
func DumpMap() error {
	return mapInstance.Dump(dumpParser, dumpCallback)
}

func init() {
	mapInstance.OpenOrCreate()
}
