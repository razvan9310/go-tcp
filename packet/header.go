// Package packet defining TCP packets and their headers.
package packet

// Control flag bit values.
const (
	CWR uint8 = 128
	ECE uint8 = 64
	URG uint8 = 32
	ACK uint8 = 16
	PSH uint8 = 8
	RST uint8 = 4
	SYN uint8 = 2
	FIN uint8 = 1
)

// Option (or lack thereof) related values.
const (
	NoSegmentSize uint16 = 0
	NoWindowScale uint8  = 0
	NoTimestamp   uint32 = 0
)

/*
Header (simplified). Contains:
  * 16-bit source port;
  * 16-bit destination port;
  * 32-bit sequence number;
  * 32-bit ack number;
  * 8-bit data offset;
  * No "reserved" field;
  * 8-bit control flags: CWR to FIN - there is no NS bit;
  * 16-bit window size;
  * 16-bit checksum;
  * 16-bit urgent pointer;
  * Up to 160-bit options; admitted option types: {0, 2, 3, 4, 8}.

All values are unsigned.
*/
type Header struct {
	SourcePort      uint16
	DestinationPort uint16
	Sequence        uint32
	Acknowledgement uint32
	DataOffset      uint8
	ControlFlags    uint8
	WindowSize      uint16
	Checksum        uint16
	UrgentPointer   uint16
	Options         []uint8
}

// NewControlFlags - generates a 8-bit control flags value from booleans.
func NewControlFlags(cwr, ece, urg, ack, psh, rst, syn, fin bool) uint8 {
	var flags uint8
	if cwr {
		flags |= CWR
	}
	if ece {
		flags |= ECE
	}
	if urg {
		flags |= URG
	}
	if ack {
		flags |= ACK
	}
	if psh {
		flags |= PSH
	}
	if rst {
		flags |= RST
	}
	if syn {
		flags |= SYN
	}
	if fin {
		flags |= FIN
	}
	return flags
}

// NewOptions - creates a new options slice from given actual values.
// It is guaranteed that the returned slice's length is a multiple of 4 (i.e. multiple of 32 bits).
func NewOptions(maxSegmentSize uint16, windowScale uint8, timestamp,
	echoTimestamp uint32) []uint8 {
	options := []uint8{}

	if maxSegmentSize != NoSegmentSize {
		options = append(options, 2, 4, uint8(maxSegmentSize>>8), uint8(maxSegmentSize))
	}

	if windowScale != NoWindowScale {
		options = append(options, 3, 3, windowScale)
	}

	if timestamp != NoTimestamp {
		options = append(options, 8, 10, uint8(timestamp>>24), uint8(timestamp>>16),
			uint8(timestamp>>8), uint8(timestamp))
		options = append(options, uint8(echoTimestamp>>24), uint8(echoTimestamp>>16),
			uint8(echoTimestamp>>8), uint8(echoTimestamp))
	}

	// End-of-options 0 value.
	options = append(options, 0)

	// Padding to a multiple of 32.
	for len(options)%4 != 0 {
		options = append(options, 0)
	}

	return options
}

// GetDataOffsetFromOptions - returns the data offset (in 32-bit words), i.e. the size of a header,
// judging by its variable length options slice.
func GetDataOffsetFromOptions(options []uint8) uint8 {
	return uint8(5 + len(options)/4)
}

// NewHeader - creates a new Header pointer from the given parameters.
// Data offset is always set to 11 (11 * 32 = 352-bit header size).
func NewHeader(source, destination uint16, sequence, ack uint32, flags uint8, window,
	urgent uint16, options []uint8) *Header {
	return &Header{SourcePort: source, DestinationPort: destination, Sequence: sequence,
		Acknowledgement: ack, DataOffset: GetDataOffsetFromOptions(options), ControlFlags: flags,
		WindowSize: window, UrgentPointer: urgent, Options: options}
}
