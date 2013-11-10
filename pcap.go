package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	magicNumber  = 0xa1b2c3d4
	magicNumberR = 0xd4c3b2a1

	magicNumberNano  = 0xa1b23c4d
	magicNumberNanoR = 0x4d3cb2a1
)

type errorReader struct {
	r   io.Reader
	err error
}

func (r *errorReader) Read(b []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}
	n, r.err = r.r.Read(b)
	return n, r.err
}

type errorWriter struct {
	w   io.Writer
	err error
}

func (w *errorWriter) Write(b []byte) (n int, err error) {
	if w.err != nil {
		return 0, w.err
	}
	n, w.err = w.w.Write(b)
	return n, w.err
}

type DLT uint32

const (
	// BSD loopback encapsulation; the link layer header is a 4-byte
	// field, in host byte order, containing a PF_ value from socket.h
	// for the network-layer protocol of the packet.
	DLT_NULL = 0
	// IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up); the 10MB in
	// the DLT_ name is historical.
	DLT_EN10MB = 1
	// AX.25 packet, with nothing preceding it.
	DLT_AX25 = 3
	// IEEE 802.5 Token Ring; the IEEE802, without _5, in the DLT_
	// name is historical.
	DLT_IEEE802 = 6
	// ARCNET Data Packets, as described by the ARCNET Trade
	// Association standard ATA 878.1-1999, but without the Starting
	// Delimiter, Information Length, or Frame Check Sequence fields,
	// and with only the first ISU of the Destination Identifier. For
	// most packet types, ARCNET Trade Association draft standard ATA
	// 878.2 is also used. See also RFC 1051 and RFC 1201; for RFC
	// 1051 frames, ATA 878.2 is not used.
	DLT_ARCNET = 7
	// SLIP, encapsulated with a LINKTYPE_SLIP header.
	DLT_SLIP = 8
	// PPP, as per RFC 1661 and RFC 1662; if the first 2 bytes are
	// 0xff and 0x03, it's PPP in HDLC-like framing, with the PPP
	// header following those two bytes, otherwise it's PPP without
	// framing, and the packet begins with the PPP header.
	DLT_PPP = 9
	// FDDI, as specified by ANSI INCITS 239-1994.
	DLT_FDDI = 10
	// PPP in HDLC-like framing, as per RFC 1662, or Cisco PPP with
	// HDLC framing, as per section 4.3.1 of RFC 1547; the first byte
	// will be 0xFF for PPP in HDLC-like framing, and will be 0x0F or
	// 0x8F for Cisco PPP with HDLC framing.
	DLT_PPP_SERIAL = 50
	// PPPoE; the packet begins with a PPPoE header, as per RFC 2516.
	DLT_PPP_ETHER = 51
	// RFC 1483 LLC/SNAP-encapsulated ATM; the packet begins with an
	// IEEE 802.2 LLC header.
	DLT_ATM_RFC1483 = 100
	// Raw IP; the packet begins with an IPv4 or IPv6 header, with the
	// "version" field of the header indicating whether it's an IPv4
	// or IPv6 header.
	DLT_RAW = 101
	// Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547.
	DLT_C_HDLC = 104
	// IEEE 802.11 wireless LAN.
	DLT_IEEE802_11 = 105
	// Frame Relay
	DLT_FRELAY = 107
	// OpenBSD loopback encapsulation; the link-layer header is a
	// 4-byte field, in network byte order, containing a PF_ value
	// from OpenBSD's socket.h for the network-layer protocol of the
	// packet.
	DLT_LOOP = 108
	// Linux "cooked" capture encapsulation.
	DLT_LINUX_SLL = 113
	// Apple LocalTalk; the packet begins with an AppleTalk LocalTalk
	// Link Access Protocol header, as described in chapter 1 of
	// Inside AppleTalk, Second Edition.
	DLT_LTALK = 114
	// OpenBSD pflog; the link-layer header contains a "struct
	// pfloghdr" structure, as defined by the host on which the file
	// was saved. (This differs from operating system to operating
	// system and release to release; there is nothing in the file to
	// indicate what the layout of that structure is.)
	DLT_PFLOG = 117
	// Prism monitor mode information followed by an 802.11 header.
	DLT_PRISM_HEADER = 119
	// RFC 2625 IP-over-Fibre Channel, with the link-layer header
	// being the Network_Header as described in that RFC.
	DLT_IP_OVER_FC = 122
	// ATM traffic, encapsulated as per the scheme used by SunATM
	// devices.
	DLT_SUNATM = 123
	// Radiotap link-layer information followed by an 802.11 header.
	DLT_IEEE802_11_RADIO = 127
	// ARCNET Data Packets, as described by the ARCNET Trade
	// Association standard ATA 878.1-1999, but without the Starting
	// Delimiter, Information Length, or Frame Check Sequence fields,
	// with only the first ISU of the Destination Identifier, and with
	// an extra two-ISU "offset" field following the Destination
	// Identifier. For most packet types, ARCNET Trade Association
	// draft standard ATA 878.2 is also used; however, no exception
	// frames are supplied, and reassembled frames, rather than
	// fragments, are supplied. See also RFC 1051 and RFC 1201; for
	// RFC 1051 frames, ATA 878.2 is not used.
	DLT_ARCNET_LINUX = 129
	// Apple IP-over-IEEE 1394 cooked header.
	DLT_APPLE_IP_OVER_IEEE1394 = 138
	// Signaling System 7 Message Transfer Part Level 2, as specified
	// by ITU-T Recommendation Q.703, preceded by a pseudo-header.
	DLT_MTP2_WITH_PHDR = 139
	// Signaling System 7 Message Transfer Part Level 2, as specified
	// by ITU-T Recommendation Q.703.
	DLT_MTP2 = 140
	// Signaling System 7 Message Transfer Part Level 3, as specified
	// by ITU-T Recommendation Q.704, with no MTP2 header preceding
	// the MTP3 packet.
	DLT_MTP3 = 141
	// Signaling System 7 Signalling Connection Control Part, as
	// specified by ITU-T Recommendation Q.711, ITU-T Recommendation
	// Q.712, ITU-T Recommendation Q.713, and ITU-T Recommendation
	// Q.714, with no MTP3 or MTP2 headers preceding the SCCP packet.
	DLT_SCCP = 142
	// DOCSIS MAC frames, as described by the DOCSIS 3.0 MAC and Upper
	// Layer Protocols Interface Specification.
	DLT_DOCSIS = 143
	// Linux-IrDA packets, with a LINKTYPE_LINUX_IRDA header, with the
	// payload for IrDA frames beginning with by the IrLAP header as
	// defined by IrDA Data Specifications, including the IrDA Link
	// Access Protocol specification.
	DLT_LINUX_IRDA = 144
	// AVS monitor mode information followed by an 802.11 header.
	DLT_IEEE802_11_RADIO_AVS = 163
	// BACnet MS/TP frames, as specified by section 9.3 MS/TP Frame
	// Format of ANSI/ASHRAE Standard 135, BACnet® - A Data
	// Communication Protocol for Building Automation and Control
	// Networks, including the preamble and, if present, the Data CRC.
	DLT_BACNET_MS_TP = 165
	// PPP in HDLC-like encapsulation, but with the 0xff address byte
	// replaced by a direction indication - 0x00 for incoming and 0x01
	// for outgoing.
	DLT_PPP_PPPD = 166
	// General Packet Radio Service Logical Link Control, as defined
	// by 3GPP TS 04.64.
	DLT_GPRS_LLC = 169
	// Link Access Procedures on the D Channel (LAPD) frames, as
	// specified by ITU-T Recommendation Q.920 and ITU-T
	// Recommendation Q.921, captured via vISDN, with a
	// LINKTYPE_LINUX_LAPD header, followed by the Q.921 frame,
	// starting with the address field.
	DLT_LINUX_LAPD = 177
	// Bluetooth HCI UART transport layer; the frame contains an HCI
	// packet indicator byte, as specified by Volume 4, part A of the
	// Core Version 4.0 of the Bluetooth specifications, followed by
	// an HCI packet of the specified packet type, as specified by
	// Volume 2, Part E of the same document.
	DLT_BLUETOOTH_HCI_H4 = 187
	// USB packets, beginning with a Linux USB header, as specified by
	// the struct usbmon_packet in the Documentation/usb/usbmon.txt
	// file in the Linux source tree. Only the first 48 bytes of that
	// header are present. All fields in the header are in the host
	// byte order for the pcap file, as specified by the file's magic
	// number, or for the section of the pcap-ng file, as specified by
	// the Section Header Block.
	DLT_USB_LINUX = 189
	// Per-Packet Information information, as specified by the
	// Per-Packet Information Header Specification, followed by a
	// packet with the LINKTYPE_ value specified by the pph_dlt field
	// of that header.
	DLT_PPI = 192
	// IEEE 802.15.4 wireless Personal Area Network, with each packet
	// having the FCS at the end of the frame.
	DLT_IEEE802_15_4 = 195
	// Various link-layer types, with a pseudo-header, for SITA.
	DLT_SITA = 196
	// Various link-layer types, with a pseudo-header, for Endace DAG
	// cards; encapsulates Endace ERF records.
	DLT_ERF = 197
	// Bluetooth HCI UART transport layer; the frame contains a 4-byte
	// direction field, in network byte order (big-endian), the
	// low-order bit of which is set if the frame was sent from the
	// host to the controller and clear if the frame was received by
	// the host from the controller, followed by an HCI packet
	// indicator byte, as specified by Volume 4, part A of the Core
	// Version 4.0 of the Bluetooth specifications, followed by an HCI
	// packet of the specified packet type, as specified by Volume 2,
	// Part E of the same document.
	DLT_BLUETOOTH_HCI_H4_WITH_PHDR = 201
	// AX.25 packet, with a 1-byte KISS header containing a type
	// indicator.
	DLT_AX25_KISS = 202
	// Link Access Procedures on the D Channel (LAPD) frames, as
	// specified by ITU-T Recommendation Q.920 and ITU-T
	// Recommendation Q.921, starting with the address field, with no
	// pseudo-header.
	DLT_LAPD = 203
	// PPP, as per RFC 1661 and RFC 1662, preceded with a one-byte
	// pseudo-header with a zero value meaning "received by this host"
	// and a non-zero value meaning "sent by this host".
	DLT_PPP_WITH_DIR = 204
	// Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547,
	// preceded with a one-byte pseudo-header with a zero value
	// meaning "received by this host" and a non-zero value meaning
	// "sent by this host".
	DLT_C_HDLC_WITH_DIR = 205
	// Frame Relay, preceded with a one-byte pseudo-header with a zero
	// value meaning "received by this host" and a non-zero value
	// meaning "sent by this host".
	DLT_FRELAY_WITH_DIR = 206
	// IPMB over an I2C circuit, with a Linux-specific pseudo-header.
	DLT_IPMB_LINUX = 209
	// IEEE 802.15.4 wireless Personal Area Network, with each packet
	// having the FCS at the end of the frame, and with the PHY-level
	// data for non-ASK PHYs (4 octets of 0 as preamble, one octet of
	// SFD, one octet of frame length + reserved bit) preceding the
	// MAC-layer data (starting with the frame control field).
	DLT_IEEE802_15_4_NONASK_PHY = 215
	// USB packets, beginning with a Linux USB header, as specified by
	// the struct usbmon_packet in the Documentation/usb/usbmon.txt
	// file in the Linux source tree. All 64 bytes of the header are
	// present. All fields in the header are in the host byte order
	// for the pcap file, as specified by the file's magic number, or
	// for the section of the pcap-ng file, as specified by the
	// Section Header Block. For isochronous transfers, the ndesc
	// field specifies the number of isochronous descriptors that
	// follow.
	DLT_USB_LINUX_MMAPPED = 220
	// Fibre Channel FC-2 frames, beginning with a Frame_Header.
	DLT_FC_2 = 224
	// Fibre Channel FC-2 frames, beginning an encoding of the SOF,
	// followed by a Frame_Header, and ending with an encoding of the
	// SOF.
	DLT_FC_2_WITH_FRAME_DELIMS = 225
	// Solaris ipnet pseudo-header, followed by an IPv4 or IPv6
	// datagram.
	DLT_IPNET = 226
	// CAN (Controller Area Network) frames, with a pseudo-header as
	// supplied by Linux SocketCAN.
	DLT_CAN_SOCKETCAN = 227
	// Raw IPv4; the packet begins with an IPv4 header.
	DLT_IPV4 = 228
	// Raw IPv6; the packet begins with an IPv6 header.
	DLT_IPV6 = 229
	// IEEE 802.15.4 wireless Personal Area Network, without the FCS
	// at the end of the frame.
	DLT_IEEE802_15_4_NOFCS = 230
	// Raw D-Bus messages, starting with the endianness flag, followed
	// by the message type, etc., but without the authentication
	// handshake before the message sequence.
	DLT_DBUS = 231
	// DVB-CI (DVB Common Interface for communication between a PC
	// Card module and a DVB receiver), with the message format
	// specified by the PCAP format for DVB-CI specification.
	DLT_DVB_CI = 235
	// Variant of 3GPP TS 27.010 multiplexing protocol (similar to,
	// but not the same as, 27.010).
	DLT_MUX27010 = 236
	// D_PDUs as described by NATO standard STANAG 5066, starting with
	// the synchronization sequence, and including both header and
	// data CRCs. The current version of STANAG 5066 is
	// backwards-compatible with the 1.0.2 version, although newer
	// versions are classified.
	DLT_STANAG_5066_D_PDU = 237
	// Linux netlink NETLINK NFLOG socket log messages.
	DLT_NFLOG = 239
	// Pseudo-header for Hilscher Gesellschaft für Systemautomation
	// mbH netANALYZER devices, followed by an Ethernet frame,
	// beginning with the MAC header and ending with the FCS.
	DLT_NETANALYZER = 240
	// Pseudo-header for Hilscher Gesellschaft für Systemautomation
	// mbH netANALYZER devices, followed by an Ethernet frame,
	// beginning with the preamble, SFD, and MAC header, and ending
	// with the FCS.
	DLT_NETANALYZER_TRANSPARENT = 241
	// IP-over-InfiniBand, as specified by RFC 4391 section 6.
	DLT_IPOIB = 242
	// MPEG-2 Transport Stream transport packets, as specified by ISO
	// 13818-1/ITU-T Recommendation H.222.0 (see table 2-2 of section
	// 2.4.3.2 "Transport Stream packet layer").
	DLT_MPEG_2_TS = 243
	// Pseudo-header for ng4T GmbH's UMTS Iub/Iur-over-ATM and
	// Iub/Iur-over-IP format as used by their ng40 protocol tester,
	// followed by frames for the Frame Protocol as specified by 3GPP
	// TS 25.427 for dedicated channels and 3GPP TS 25.435 for
	// common/shared channels in the case of ATM AAL2 or UDP traffic,
	// by SSCOP packets as specified by ITU-T Recommendation Q.2110
	// for ATM AAL5 traffic, and by NBAP packets for SCTP traffic.
	DLT_NG40 = 244
	// Pseudo-header for NFC LLCP packet captures, followed by frame
	// data for the LLCP Protocol as specified by
	// NFCForum-TS-LLCP_1.1.
	DLT_NFC_LLCP = 245
	// Raw InfiniBand frames, starting with the Local Routing Header,
	// as specified in Chapter 5 "Data packet format" of InfiniBand™
	// Architectural Specification Release 1.2.1 Volume 1 - General
	// Specifications.
	DLT_INFINIBAND = 247
	// SCTP packets, as defined by RFC 4960, with no lower-level
	// protocols such as IPv4 or IPv6.
	DLT_SCTP = 248
	// USB packets, beginning with a USBPcap header.
	DLT_USBPCAP = 249
	// Serial-line packet header for the Schweitzer Engineering
	// Laboratories "RTAC" product, followed by a payload for one of a
	// number of industrial control protocols.
	DLT_RTAC_SERIAL = 250
	// Bluetooth Low Energy air interface Link Layer packets, in the
	// format described in section 2.1 "PACKET FORMAT" of volume 6 of
	// the Bluetooth Specification Version 4.0 (see PDF page 2200),
	// but without the Preamble.
	DLT_BLUETOOTH_LE_LL = 251
)

type Payload interface {
	Payload() []byte
}

type Bytes []byte

func (b Bytes) Payload() []byte {
	return b
}

type GlobalHeader struct {
	VersionMajor      uint16
	VersionMinor      uint16
	ZoneCorrection    int32
	TimestampAccuracy uint32
	SnapshotLength    uint32
	Network           DLT
	Nanosecond        bool
	ByteOrder         binary.ByteOrder
}

type PacketHeader struct {
	Timestamp      time.Time
	SavedLength    uint32
	OriginalLength uint32
}

type Packet struct {
	Header PacketHeader
	Data   Payload
}

type Reader struct {
	Header GlobalHeader
	r      io.Reader
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r: r}
}

func (p *Reader) ParseHeader() error {
	r := &errorReader{r: p.r}

	var magic uint32
	p.Header.ByteOrder = binary.LittleEndian
	binary.Read(r, p.Header.ByteOrder, &magic)

	switch magic {
	case magicNumberR:
		p.Header.ByteOrder = binary.BigEndian
		magic = magicNumber
	case magicNumberNanoR:
		p.Header.ByteOrder = binary.BigEndian
		magic = magicNumberNano
	}

	if magic == magicNumberNano {
		p.Header.Nanosecond = true
	} else if magic != magicNumber {
		return fmt.Errorf("Invalid magic number: %x", magic)
	}

	binary.Read(r, p.Header.ByteOrder, &p.Header.VersionMajor)
	binary.Read(r, p.Header.ByteOrder, &p.Header.VersionMinor)
	binary.Read(r, p.Header.ByteOrder, &p.Header.ZoneCorrection)
	binary.Read(r, p.Header.ByteOrder, &p.Header.TimestampAccuracy)
	binary.Read(r, p.Header.ByteOrder, &p.Header.SnapshotLength)
	binary.Read(r, p.Header.ByteOrder, &p.Header.Network)

	return r.err
}

func (p *Reader) ReadPacket() (Packet, error) {
	h := PacketHeader{}
	r := &errorReader{r: p.r}

	var ts_sec, ts_usec uint32
	binary.Read(r, p.Header.ByteOrder, &ts_sec)
	binary.Read(r, p.Header.ByteOrder, &ts_usec)
	if !p.Header.Nanosecond {
		ts_usec *= 1e3
	}
	ts_sec = uint32(int64(ts_sec) + int64(p.Header.ZoneCorrection))
	h.Timestamp = time.Unix(int64(ts_sec), int64(ts_usec))
	binary.Read(r, p.Header.ByteOrder, &h.SavedLength)
	binary.Read(r, p.Header.ByteOrder, &h.OriginalLength)

	// Check error here so we don't allocate absurd amounts of memory
	// later on
	if r.err != nil {
		return Packet{}, r.err
	}

	data := make([]byte, h.SavedLength)
	binary.Read(r, p.Header.ByteOrder, &data)

	return Packet{h, Bytes(data)}, r.err
}

type Writer struct {
	Header GlobalHeader
	w      io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{
		Header: GlobalHeader{
			SnapshotLength: 65535,
			VersionMajor:   2,
			VersionMinor:   4,
			ByteOrder:      binary.LittleEndian,
		},
		w: w,
	}
}

func (p *Writer) WriteHeader() error {
	magic := uint32(magicNumber)
	if p.Header.Nanosecond {
		magic = magicNumberNano
	}
	w := &errorWriter{w: p.w}
	binary.Write(w, p.Header.ByteOrder, magic)
	binary.Write(w, p.Header.ByteOrder, p.Header.VersionMajor)
	binary.Write(w, p.Header.ByteOrder, p.Header.VersionMinor)
	binary.Write(w, p.Header.ByteOrder, p.Header.ZoneCorrection)
	binary.Write(w, p.Header.ByteOrder, p.Header.TimestampAccuracy)
	binary.Write(w, p.Header.ByteOrder, p.Header.SnapshotLength)
	binary.Write(w, p.Header.ByteOrder, p.Header.Network)

	return w.err
}

func (p *Writer) WritePacket(packet Packet) error {
	payload := packet.Data.Payload()
	packet.Header.OriginalLength = uint32(len(payload))
	if packet.Header.OriginalLength > p.Header.SnapshotLength {
		payload = payload[:p.Header.SnapshotLength]
	}
	packet.Header.SavedLength = uint32(len(payload))

	if packet.Header.Timestamp.IsZero() {
		packet.Header.Timestamp = time.Now()
	}

	ts_sec := uint32(packet.Header.Timestamp.Unix())
	ts_usec := uint32(packet.Header.Timestamp.Nanosecond())
	if !p.Header.Nanosecond {
		ts_usec /= 1e3
	}

	w := &errorWriter{w: p.w}
	binary.Write(w, p.Header.ByteOrder, ts_sec)
	binary.Write(w, p.Header.ByteOrder, ts_usec)
	binary.Write(w, p.Header.ByteOrder, packet.Header.SavedLength)
	binary.Write(w, p.Header.ByteOrder, packet.Header.OriginalLength)
	w.Write(payload)

	return w.err
}
