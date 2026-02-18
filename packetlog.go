package main

import (
	"fmt"
	"net"
	"os"
	"sync"
)

type CapturedPacket struct {
	Data []byte
	Addr net.Addr
}

type InterceptConn struct {
	net.PacketConn
	LogPackets     bool
	capturedPacket *CapturedPacket
	mutex          sync.Mutex
}

// Instead of sending the packet, store it
func (i *InterceptConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if i.LogPackets {
		//fmt.Printf("[INTERCEPTED] %d bytes to %s:\n%x\n", len(b), addr.String(), b)
		savePacketToFile(b)

		offset := 0
		for offset < len(b) {
			next, err := parseQUICPacket(b, offset)
			if err != nil {
				fmt.Println("  parsing error:", err)
				break
			}
			offset = next
		}
	}

	// Capture the packet instead of sending
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.capturedPacket = &CapturedPacket{
		Data: append([]byte(nil), b...), // copy
		Addr: addr,
	}
	return len(b), nil
}

// Allow external code to get and clear the captured packet
func (i *InterceptConn) CaptureNextPacket() *CapturedPacket {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	pkt := i.capturedPacket
	i.capturedPacket = nil
	return pkt
}

func (i *InterceptConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := i.PacketConn.ReadFrom(b)
	if err == nil && i.LogPackets {
		fmt.Printf("[RECV] %d bytes from %s:\n%x\n", n, addr.String(), b[:n])
	}
	return n, addr, err
}

func savePacketToFile(b []byte) error {
	f, err := os.OpenFile("captured_quic_packets.bin", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(b)
	return err
}

func parseQUICPacket(data []byte, offset int) (nextOffset int, err error) {
	if offset+6 > len(data) {
		return offset, fmt.Errorf("too short for QUIC header")
	}

	first := data[offset]
	if first&0x80 == 0 { // short header
		fmt.Printf("Short Header (offset %d): %02x\n", offset, first)
		return offset + 1, nil // placeholder
	}


	dcidLen := int(data[offset+5])
	pos := offset + 6

	if pos+dcidLen >= len(data) {
		return offset, fmt.Errorf("dcid overflow")
	}
	pos += dcidLen

	if pos >= len(data) {
		return offset, fmt.Errorf("missing scid length")
	}
	scidLen := int(data[pos])
	pos++

	if pos+scidLen >= len(data) {
		return offset, fmt.Errorf("scid overflow")
	}
	pos += scidLen

	return len(data), nil
}
