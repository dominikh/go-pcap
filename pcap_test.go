package pcap

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"os"
	"time"
)

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
