//go:build windows

package vpn

import (
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Dynamic WFP (Windows Filtering Platform) kill switch.
//
// A session opened with FWPM_SESSION_FLAG_DYNAMIC is owned by the kernel for
// the lifetime of the handle: if Ghostline exits or crashes, Windows deletes
// the sublayer and every filter automatically.
const (
	fwpmSessionFlagDynamic = 0x00000001
	fwpActionBlock         = 0x00001001
	fwpActionPermit        = 0x00001002

	fwpUint8        = 1
	fwpUint64       = 4
	fwpByteBlobType = 12
	fwpV4AddrMask   = 256
	fwpV6AddrMask   = 257

	fwpMatchEqual = 0

	ifTypePropVirtual = 53
	ifTypeTunnel      = 131
)

var (
	fwpuclnt                        = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0             = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0            = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd0            = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0              = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmGetAppIdFromFileName0   = fwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0             = fwpuclnt.NewProc("FwpmFreeMemory0")
	layerALEAuthConnectV4           = mustGUID("{c38d57d1-05a7-4c33-904f-7fbceee60e82}")
	layerALEAuthConnectV6           = mustGUID("{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}")
	condIPRemoteAddress             = mustGUID("{b235ae9a-1d64-49b8-a44c-5ff3d9095045}")
	condIPLocalInterface            = mustGUID("{4cd62a49-59c3-4969-b7f3-bda5d32890a4}")
	condALEAppID                    = mustGUID("{d78e1e87-8644-4ea5-9437-d809ecefc971}")
	ghostlineVPNSubLayerKey         = mustGUID("{7c2e41f8-8c9a-4f3b-9b5e-3d8a7e41c901}")
)

func mustGUID(s string) windows.GUID {
	g, err := windows.GUIDFromString(s)
	if err != nil {
		panic(err)
	}
	return g
}

// Win32 SDK (x64 ABI) structs for fwpmtypes.h / fwptypes.h.
type fwpByteBlob struct {
	size uint32
	_    uint32
	data uintptr
}

type fwpValue0 struct {
	typ uint32
	_   uint32
	val uint64
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processId            uint32
	_                    uint32
	sid                  uintptr
	username             *uint16
	kernelMode           int32
	_2                   uint32
}

type fwpmSubLayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	_            uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
	_2           [6]byte
}

type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	_              uint32
	conditionValue fwpValue0
}

type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID
}

type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	_                   uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	_2                  uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	_3                  uint32
	rawContext          uint64
	_contextPad         uint64
	reserved            *windows.GUID
	filterId            uint64
	effectiveWeight     fwpValue0
}

type fwpV4AddrAndMask struct {
	addr uint32
	mask uint32
}

type fwpV6AddrAndMask struct {
	addr         [16]byte
	prefixLength uint8
}

type killSwitch struct {
	mu       sync.Mutex
	engine   uintptr
	seenLUID map[uint64]bool
	closed   bool
}

func startKillSwitch(openvpnBinary string) (*killSwitch, error) {
	namePtr, _ := windows.UTF16PtrFromString("Ghostline VPN Kill Switch")
	sess := fwpmSession0{
		displayData: fwpmDisplayData0{name: namePtr},
		flags:       fwpmSessionFlagDynamic,
	}
	var engine uintptr
	r, _, _ := procFwpmEngineOpen0.Call(0, 0, 0, uintptr(unsafe.Pointer(&sess)), uintptr(unsafe.Pointer(&engine)))
	runtime.KeepAlive(namePtr)
	if r != 0 {
		return nil, fmt.Errorf("FwpmEngineOpen0: 0x%x", r)
	}
	ks := &killSwitch{engine: engine, seenLUID: map[uint64]bool{}}
	if err := ks.init(openvpnBinary); err != nil {
		_ = ks.Close()
		return nil, err
	}
	return ks, nil
}

func (k *killSwitch) init(openvpnBinary string) error {
	subName, _ := windows.UTF16PtrFromString("Ghostline VPN Kill Switch")
	sub := fwpmSubLayer0{
		subLayerKey: ghostlineVPNSubLayerKey,
		displayData: fwpmDisplayData0{name: subName},
		weight:      0xFFFF,
	}
	r, _, _ := procFwpmSubLayerAdd0.Call(k.engine, uintptr(unsafe.Pointer(&sub)), 0)
	runtime.KeepAlive(subName)
	if r != 0 {
		return fmt.Errorf("FwpmSubLayerAdd0: 0x%x", r)
	}

	// Permit loopback (Ghostline DNS 127.0.0.1, proxy, management socket).
	if err := k.permitV4Prefix(15, "127.0.0.0/8"); err != nil {
		return err
	}
	if err := k.permitV6Prefix(15, "::1/128"); err != nil {
		return err
	}

	// Permit OpenVPN itself to dial and reconnect to the VPN server.
	if err := k.permitApp(14, openvpnBinary); err != nil {
		return err
	}

	// Permit existing OpenVPN / Wintun / TAP virtual adapters (refreshed again
	// when the tunnel assigns an IP in case Wintun is created dynamically).
	if err := k.Refresh(); err != nil {
		return err
	}

	// Permit LAN / link-local / DHCP broadcast so local router/LAN stay reachable
	// while every public IP outside the tunnel is blocked.
	for _, p := range []string{"192.168.0.0/16", "172.16.0.0/12", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"} {
		if err := k.permitV4Prefix(10, p); err != nil {
			return err
		}
	}
	for _, p := range []string{"fe80::/10", "ff00::/8"} {
		if err := k.permitV6Prefix(10, p); err != nil {
			return err
		}
	}

	// Default-deny every other outbound IPv4 and IPv6 connection.
	if err := k.addFilter(layerALEAuthConnectV4, 1, fwpActionBlock, nil); err != nil {
		return err
	}
	return k.addFilter(layerALEAuthConnectV6, 1, fwpActionBlock, nil)
}

// Refresh permits any newly created OpenVPN / Wintun / TAP adapter LUID.
func (k *killSwitch) Refresh() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed || k.engine == 0 {
		return nil
	}
	luids, err := findVPNAdapterLUIDs()
	if err != nil {
		return err
	}
	for _, luid := range luids {
		if k.seenLUID[luid] {
			continue
		}
		if err := k.permitLUID(13, luid); err != nil {
			return err
		}
		k.seenLUID[luid] = true
	}
	return nil
}

func (k *killSwitch) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed || k.engine == 0 {
		return nil
	}
	k.closed = true
	r, _, _ := procFwpmEngineClose0.Call(k.engine)
	k.engine = 0
	if r != 0 {
		return fmt.Errorf("FwpmEngineClose0: 0x%x", r)
	}
	return nil
}

func (k *killSwitch) permitApp(weight uint8, exePath string) error {
	exePtr, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return err
	}
	var blob uintptr
	r, _, _ := procFwpmGetAppIdFromFileName0.Call(uintptr(unsafe.Pointer(exePtr)), uintptr(unsafe.Pointer(&blob)))
	runtime.KeepAlive(exePtr)
	if r != 0 {
		return fmt.Errorf("FwpmGetAppIdFromFileName0: 0x%x", r)
	}
	defer procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&blob)))
	conds := []fwpmFilterCondition0{{
		fieldKey:       condALEAppID,
		matchType:      fwpMatchEqual,
		conditionValue: fwpValue0{typ: fwpByteBlobType, val: uint64(blob)},
	}}
	if err := k.addFilter(layerALEAuthConnectV4, weight, fwpActionPermit, conds); err != nil {
		return err
	}
	return k.addFilter(layerALEAuthConnectV6, weight, fwpActionPermit, conds)
}

func (k *killSwitch) permitLUID(weight uint8, luid uint64) error {
	v := luid
	conds := []fwpmFilterCondition0{{
		fieldKey:       condIPLocalInterface,
		matchType:      fwpMatchEqual,
		conditionValue: fwpValue0{typ: fwpUint64, val: uint64(uintptr(unsafe.Pointer(&v)))},
	}}
	if err := k.addFilter(layerALEAuthConnectV4, weight, fwpActionPermit, conds); err != nil {
		return err
	}
	err := k.addFilter(layerALEAuthConnectV6, weight, fwpActionPermit, conds)
	runtime.KeepAlive(&v)
	return err
}

func (k *killSwitch) permitV4Prefix(weight uint8, cidr string) error {
	m, err := parseV4Mask(cidr)
	if err != nil {
		return err
	}
	conds := []fwpmFilterCondition0{{
		fieldKey:       condIPRemoteAddress,
		matchType:      fwpMatchEqual,
		conditionValue: fwpValue0{typ: fwpV4AddrMask, val: uint64(uintptr(unsafe.Pointer(&m)))},
	}}
	err = k.addFilter(layerALEAuthConnectV4, weight, fwpActionPermit, conds)
	runtime.KeepAlive(&m)
	return err
}

func (k *killSwitch) permitV6Prefix(weight uint8, cidr string) error {
	m, err := parseV6Mask(cidr)
	if err != nil {
		return err
	}
	conds := []fwpmFilterCondition0{{
		fieldKey:       condIPRemoteAddress,
		matchType:      fwpMatchEqual,
		conditionValue: fwpValue0{typ: fwpV6AddrMask, val: uint64(uintptr(unsafe.Pointer(&m)))},
	}}
	err = k.addFilter(layerALEAuthConnectV6, weight, fwpActionPermit, conds)
	runtime.KeepAlive(&m)
	return err
}

func (k *killSwitch) addFilter(layer windows.GUID, weight uint8, action uint32, conds []fwpmFilterCondition0) error {
	namePtr, _ := windows.UTF16PtrFromString("Ghostline VPN")
	var condPtr *fwpmFilterCondition0
	if len(conds) > 0 {
		condPtr = &conds[0]
	}
	f := fwpmFilter0{
		displayData:         fwpmDisplayData0{name: namePtr},
		layerKey:            layer,
		subLayerKey:         ghostlineVPNSubLayerKey,
		weight:              fwpValue0{typ: fwpUint8, val: uint64(weight)},
		numFilterConditions: uint32(len(conds)),
		filterCondition:     condPtr,
		action:              fwpmAction0{typ: action},
	}
	var id uint64
	r, _, _ := procFwpmFilterAdd0.Call(k.engine, uintptr(unsafe.Pointer(&f)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(namePtr)
	runtime.KeepAlive(conds)
	if r != 0 {
		return fmt.Errorf("FwpmFilterAdd0: 0x%x", r)
	}
	return nil
}

func parseV4Mask(cidr string) (fwpV4AddrAndMask, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil || !p.Addr().Is4() {
		return fwpV4AddrAndMask{}, fmt.Errorf("bad v4 prefix %q", cidr)
	}
	b := p.Addr().As4()
	addr := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	var mask uint32
	if p.Bits() > 0 {
		mask = ^uint32(0) << (32 - p.Bits())
	}
	return fwpV4AddrAndMask{addr: addr & mask, mask: mask}, nil
}

func parseV6Mask(cidr string) (fwpV6AddrAndMask, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil || !p.Addr().Is6() {
		return fwpV6AddrAndMask{}, fmt.Errorf("bad v6 prefix %q", cidr)
	}
	return fwpV6AddrAndMask{addr: p.Masked().Addr().As16(), prefixLength: uint8(p.Bits())}, nil
}

func isVPNAdapter(ifType uint32, desc, alias string) bool {
	if ifType != ifTypePropVirtual && ifType != ifTypeTunnel {
		return false
	}
	s := strings.ToLower(desc + " " + alias)
	return strings.Contains(s, "openvpn") || strings.Contains(s, "tap-windows") || strings.Contains(s, "wintun") || strings.Contains(s, "ovpn")
}

func findVPNAdapterLUIDs() ([]uint64, error) {
	size := uint32(15 * 1024)
	var buf []byte
	for i := 0; i < 5; i++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || i == 4 {
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
	}
	var out []uint64
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		desc := windows.UTF16PtrToString(aa.Description)
		alias := windows.UTF16PtrToString(aa.FriendlyName)
		if isVPNAdapter(aa.IfType, desc, alias) {
			out = append(out, aa.Luid)
		}
	}
	return out, nil
}
