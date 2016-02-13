package packet

import (
	"math/rand"
	"reflect"
	"testing"
)

func TestNewControlFlags(t *testing.T) {
	var flags = NewControlFlags(true, false, false, false, false, false, false, false)
	if flags != 128 {
		t.Errorf("CWR option bit not set correctly: %d", flags)
	}

	flags = NewControlFlags(false, true, false, false, false, false, false, false)
	if flags != 64 {
		t.Errorf("ECE option bit not set correctly: %d", flags)
	}

	flags = NewControlFlags(false, false, true, false, false, false, false, false)
	if flags != 32 {
		t.Errorf("URG option bit not set correctly: %d", flags)
	}

	flags = NewControlFlags(false, false, false, true, false, false, false, false)
	if flags != 16 {
		t.Errorf("ACK option bit not set correctly: %d", flags)
	}

	flags = NewControlFlags(false, false, false, false, true, false, false, false)
	if flags != 8 {
		t.Errorf("PSH option bit not set correctly: %d", flags)
	}

	flags = NewControlFlags(false, false, false, false, false, true, false, false)
	if flags != 4 {
		t.Errorf("RST option bit not set correctly: %d", flags)
	}

	flags = NewControlFlags(false, false, false, false, false, false, true, false)
	if flags != 2 {
		t.Errorf("SYN option bit not set correctly: %d", flags)
	}

	flags = NewControlFlags(false, false, false, false, false, false, false, true)
	if flags != 1 {
		t.Errorf("FIN option bit not set correctly: %d", flags)
	}

	flags = NewControlFlags(false, false, false, false, false, false, false, false)
	if flags != 0 {
		t.Errorf("Default (empty) flags not 0, but %d", flags)
	}

	flags = NewControlFlags(true, true, true, true, true, true, true, true)
	if flags != 255 {
		t.Errorf("Full flags not 255 (11111111 in binary), but %d", flags)
	}
}

func TestNewOptions(t *testing.T) {
	var options = NewOptions(NoSegmentSize, NoWindowScale, NoTimestamp, NoTimestamp)
	if !reflect.DeepEqual(options, []uint8{0, 0, 0, 0}) {
		t.Errorf("Default (empty) options not [0 0 0 0], but %d", options)
	}

	options = NewOptions(65535, NoWindowScale, NoTimestamp, NoTimestamp)
	if !reflect.DeepEqual(options, []uint8{2, 4, 255, 255, 0, 0, 0, 0}) {
		t.Errorf("Invalid options slice with max_seg_size = 65535 (and no other option). "+
			"Expected: [2 4 255 255 0 0 0 0]. Actual: %d", options)
	}

	options = NewOptions(NoSegmentSize, 255, NoTimestamp, NoTimestamp)
	if !reflect.DeepEqual(options, []uint8{3, 3, 255, 0}) {
		t.Errorf("Invalid options slice with window_scale = 255 (and no other option). "+
			"Expected: [3 3 255 0]. Actual: %d", options)
	}

	options = NewOptions(NoSegmentSize, NoWindowScale, 4294967295, 4294967295)
	if !reflect.DeepEqual(
		options, []uint8{8, 10, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0}) {
		t.Errorf("Invalid options slice with timestamp = echo_timestamp = 4294967295 (and no "+
			"other option). Expected: [8 10 255 255 255 255 255 255 255 255 0 0]. Actual: %d",
			options)
	}

	options = NewOptions(65535, 255, 4294967295, 4294967295)
	if !reflect.DeepEqual(options, []uint8{
		2, 4, 255, 255, 3, 3, 255, 8, 10, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0}) {
		t.Errorf("Invalid options slice with max_seg_size = 65535, window_scale = 255, "+
			"timestamp = echo_timestamp = 4294967295. Expected: [2 4 255 3 3 255 8 10 255 255 "+
			"255 255 255 255 255 255 0 0 0]. Actual: %d", options)
	}
}

func TestGetDataOffsetFromOptions(t *testing.T) {
	var optionsLength = uint8(rand.Intn(21))
	optionsLength -= optionsLength % 4
	var options = make([]uint8, optionsLength)

	var dataOffset = GetDataOffsetFromOptions(options)
	if dataOffset != optionsLength/4+5 {
		t.Errorf("Invalid data offset from %d-byte options slice: %d", optionsLength, dataOffset)
	}
}

func TestNewHeader(t *testing.T) {
	var source uint16 = 65535
	var destination uint16 = 12345
	var sequence uint32 = 1000000000
	var ack uint32 = 2000000001
	var flags = NewControlFlags(true, false, true, false, false, true, true, false)
	var window uint16 = 20203
	var urgent uint16
	var options = NewOptions(65535, 255, 1234567890, 1234567890)
	var dataOffset = GetDataOffsetFromOptions(options)

	var header = NewHeader(source, destination, sequence, ack, flags, window, urgent, options)

	if header.SourcePort != source {
		t.Errorf("Invalid header source port. Expected: %d. Actual: %d.",
			source, header.SourcePort)
	}

	if header.DestinationPort != destination {
		t.Errorf("Invalid header destination port. Expected: %d. Actual: %d",
			destination, header.DestinationPort)
	}

	if header.Sequence != sequence {
		t.Errorf("Invalid header sequence number. Expected: %d. Actual: %d",
			sequence, header.Sequence)
	}

	if header.Acknowledgement != ack {
		t.Errorf("Invalid header ack number. Expected: %d. Actual: %d",
			ack, header.Acknowledgement)
	}

	if header.DataOffset != dataOffset {
		t.Errorf("Invalid data offset. Expected: %d. Actual: %d", dataOffset, header.DataOffset)
	}

	if header.ControlFlags != flags {
		t.Errorf("Invalid control flags. Expected: %d. Actual: %d", flags, header.ControlFlags)
	}

	if header.WindowSize != window {
		t.Errorf("Invalid window size. Expected: %d. Actual: %d", window, header.WindowSize)
	}

	if header.Checksum != 0 {
		t.Errorf("Invalid checksum. Expected 0. Actual: %d", header.Checksum)
	}

	if header.UrgentPointer != urgent {
		t.Errorf("Invalid urgent pointer. Expected: %d. Actual: %d", urgent, header.UrgentPointer)
	}

	if !reflect.DeepEqual(header.Options, options) {
		t.Errorf("Invalid options. Expected: %d. Actual: %d", options, header.Options)
	}
}
