package ctmap

import (
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"bytes"
	"fmt"
	"net"
	"github.com/cilium/cilium/pkg/bpf"
	"unsafe"
)

var (
	Service6Map = bpf.NewMap(MapName6 +"_services",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(CtKey6{})),
		int(unsafe.Sizeof(CtEntry{})),
		maxEntries)
)

type CtKey6 struct {
       addr    types.IPv6
       sport   uint16
       dport   uint16
       nexthdr u8proto.U8proto
       flags   uint8
}
// NewCtKey6 creates a CtKey6 with the provided ip, source port, destination port, next header, and flags.
func NewCtKey6(addr net.IP, sport uint16, dport uint16, nexthdr u8proto.U8proto, flags uint8) *CtKey6 {
	key := CtKey6{
		sport: sport,
		dport: dport,
		nexthdr: nexthdr,
		flags: flags,
	}

	copy(key.addr[:], addr.To16())

	return &key
}

// TODO: remove me - implementing bpf.MapKey here
func (k *CtKey6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *CtKey6) NewValue() bpf.MapValue    { return &CtEntry{} }

// TODO: remove me - implementing ServiceKey
func (k CtKey6) Map() *bpf.Map              { return Service6Map }

func (k *CtKey6) Convert() ServiceKey {
	n := *k
	// TODO: what more do I have to add here?
	n.sport = common.Swab16(n.sport)
	n.dport = common.Swab16(n.dport)
	return &n
}

func (k *CtKey6) String() string {
	return fmt.Sprintf("%s:%d, %d, %d, %d", k.addr, k.sport, k.dport, k.nexthdr, k.flags)
}

//TODO: remove me - finish implementing ServiceKey here.

// TODO: get rid of this and implement dump according to the Map interface.
// TODO: what is this doing??
func (key CtKey6) Dump(buffer *bytes.Buffer) bool {
	if key.nexthdr == 0 {
		return false
	}

	if key.flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			key.nexthdr.String(),
			key.addr.IP().String(),
			key.sport, key.dport),
		)

	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			key.nexthdr.String(),
			key.addr.IP().String(),
			key.dport,
			key.sport),
		)
	}

	if key.flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	return true
}
