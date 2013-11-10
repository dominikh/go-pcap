package pcap

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestHeaderParsing(t *testing.T) {
	// TODO test correct application of ZoneCorrection
	r := NewReader(bytes.NewReader(testPacket))
	if err := r.ParseHeader(); err != nil {
		t.Errorf("Parsing header should have succeeded, got %v", err)
	}

	expectedHeader := GlobalHeader{
		VersionMajor:      2,
		VersionMinor:      4,
		ZoneCorrection:    0,
		TimestampAccuracy: 0,
		SnapshotLength:    65535,
		Network:           DLT_EN10MB,
		Nanosecond:        false,
		ByteOrder:         binary.LittleEndian,
	}

	if r.Header != expectedHeader {
		t.Errorf("Expected %#v, got %#v", expectedHeader, r.Header)
	}
}

func TestPacketParsing(t *testing.T) {
	metadata := []struct {
		ts     int64
		length uint32
	}{
		{1384093900821501000, 494},
		{1384093900821508000, 66},
		{1384093900829437000, 4162},
	}

	r := NewReader(bytes.NewReader(testPacket))
	r.ParseHeader()
	var cnt int
	for {
		packet, err := r.ReadPacket()
		if err != nil {
			if err == io.EOF {
				break
			}

			t.Errorf("Unexpected error %v", err)
		}

		meta := metadata[cnt]
		if nano := packet.Header.Timestamp.UnixNano(); meta.ts != nano {
			t.Errorf("Expected timestamp %d, got %d", meta.ts, nano)
		}
		sl, ol := packet.Header.SavedLength, packet.Header.OriginalLength
		if sl != meta.length || ol != meta.length {
			t.Errorf("Expected SavedLength and OriginalLength %d, got %d and %d", meta.length, sl, ol)
		}

		cnt++
	}

	if cnt != len(metadata) {
		t.Errorf("Expected to read %d packets, read %d", len(metadata), cnt)
	}
}

func TestTimezone(t *testing.T) {
	const time1 = 1384093900821501000
	const time2 = time1 - 3600e9

	r := NewReader(bytes.NewReader(testPacket))
	r.ParseHeader()
	packet, _ := r.ReadPacket()
	if nano := packet.Header.Timestamp.UnixNano(); nano != time1 {
		t.Errorf("Expected timestamp %d, got %d", time1, nano)
	}

	r = NewReader(bytes.NewReader(testPacket))
	r.ParseHeader()
	r.Header.ZoneCorrection = -3600
	packet, err := r.ReadPacket()
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if nano := packet.Header.Timestamp.UnixNano(); nano != time2 {
		t.Errorf("Expected timestamp %d, got %d", time2, nano)
	}
}

func ExampleNewWriter() {
	w := NewWriter(ioutil.Discard)
	w.Header.Network = DLT_EN10MB
	w.WriteHeader()
	// write packets here
}

func ExampleNewWriter_append() {
	// Append to an existing capture by copying the header

	f, _ := os.Open("capture.pcap")
	r := NewReader(f)
	r.ParseHeader()
	f.Close()

	f, _ = os.OpenFile("capture.pcap", os.O_APPEND, 0666)
	defer f.Close()
	w := NewWriter(f)
	w.Header = r.Header

	// write packets here
}

type Ethernet struct {
	Destination [6]byte
	Source      [6]byte
	Type        uint16
	Data        Payload
}

func (e *Ethernet) Payload() []byte {
	w := &bytes.Buffer{}
	binary.Write(w, binary.BigEndian, e.Destination)
	binary.Write(w, binary.BigEndian, e.Source)
	binary.Write(w, binary.BigEndian, e.Type)
	binary.Write(w, binary.BigEndian, e.Data.Payload())
	if len(w.Bytes()) < 60 {
		w.Write(make([]byte, 60-len(w.Bytes())))
	}
	return w.Bytes()
}

func ExampleWriter_WritePacket() {
	w := NewWriter(ioutil.Discard)
	w.Header.Network = DLT_EN10MB
	w.WriteHeader()

	// Please note that the Ethernet type is not defined in the pcap
	// package.
	frame := &Ethernet{
		Destination: [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Source:      [6]byte{1, 2, 3, 4, 5, 6},
		Type:        0x0800,
		Data:        Bytes("Actual IPv4 payload here"),
	}
	// By not explicitly specifying a header with a timestamp, the
	// current time will be used.
	w.WritePacket(Packet{Data: frame})

	w.WritePacket(Packet{
		// Specify a timestamp
		Header: PacketHeader{Timestamp: time.Unix(1234567, 0)},
		Data:   frame,
	})
}
