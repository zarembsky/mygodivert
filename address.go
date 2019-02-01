package godivert

import "fmt"

// Represents a WinDivertAddress struct
// See : https://reqrypt.org/windivert-doc.html#divert_address
// As go doesn't not support bit fields
// we use a little trick to get the Direction, Loopback, Import and PseudoChecksum fields
type WinDivertAddress struct {
	Timestamp int64
	IfIdx     uint32
	SubIfIdx  uint32
	Data      uint8
}

func (w *WinDivertAddress) String() string {
	return fmt.Sprintf("{\n"+
		"\t\tTimestamp=%d\n"+
		"\t\tInteface={IfIdx=%d SubIfIdx=%d}\n"+
		"\t\tDirection=%v\n"+
		"\t\tLoopback=%t\n"+
		"\t\tImpostor=%t\n"+
		"\t\tPseudoChecksum={IP=%t TCP=%t UDP=%t}\n"+
		"\t}",
		w.Timestamp, w.IfIdx, w.SubIfIdx, w.Direction(), w.Loopback(), w.Impostor(),
		w.PseudoIPChecksum(), w.PseudoTCPChecksum(), w.PseudoUDPChecksum())
}

// Returns the direction of the packet
// WinDivertDirectionInbound (true) for inbounds packets
// WinDivertDirectionOutbounds (false) for outbounds packets
func (w *WinDivertAddress) Direction() Direction {
	return Direction(hasBit(w.Data, 0))
}

// Returns true if the packet is a loopback packet
func (w *WinDivertAddress) Loopback() bool {
	return hasBit(w.Data, 1)
}

// Returns true if the packet is an impostor
// See https://reqrypt.org/windivert-doc.html#divert_address for more information
func (w *WinDivertAddress) Impostor() bool {
	return hasBit(w.Data, 2)
}

// Returns true if the packet uses a pseudo IP checksum
func (w *WinDivertAddress) PseudoIPChecksum() bool {
	return hasBit(w.Data, 3)
}

// Returns true if the packet uses a pseudo TCP checksum
func (w *WinDivertAddress) PseudoTCPChecksum() bool {
	return hasBit(w.Data, 4)
}

// Returns true if the packet uses a pseudo UDP checksum
func (w *WinDivertAddress) PseudoUDPChecksum() bool {
	return hasBit(w.Data, 5)
}

// Sets the bit at pos in the integer n.
func setBit(n uint8, pos uint) uint8 {
	n |= (1 << pos)
	return n
}

// Clears the bit at pos in n.
func clearBit(n uint8, pos uint) uint8 {
	n &= ^(1 << pos)
	return n
}

func hasBit(n uint8, pos uint) bool {
	val := n & (1 << pos)
	return (val > 0)
}

// Sets the direction of the packet
// WinDivertDirectionInbound (true) for inbounds packets
// WinDivertDirectionOutbounds (false) for outbounds packets
func (w *WinDivertAddress) SetDirection(direction bool) {
	if direction == true {
		w.Data = setBit(w.Data, 0)
	} else {
		w.Data = clearBit(w.Data, 0)
	}
}
