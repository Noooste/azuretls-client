package azuretls

import (
	"bytes"
	"strings"
	"testing"
)

func TestToBytes(t *testing.T) {
	var testString = "test"
	var testBytes = []byte(testString)

	if !bytes.Equal(toBytes(testString), testBytes) {
		t.Fatal("TestToBytes failed, expected: ", testBytes, ", got: ", toBytes(testString))
	}

	buf := new(bytes.Buffer)
	buf.Write(testBytes)
	got := toBytes(buf)
	if !bytes.Equal(got, testBytes) {
		t.Fatal("TestToBytes failed, expected: ", string(testBytes), ", got: ", string(got))
	}

	buf2 := bytes.Buffer{}
	buf2.Write(testBytes)
	got = toBytes(buf2)
	if !bytes.Equal(got, testBytes) {
		t.Fatal("TestToBytes failed, expected: ", string(testBytes), ", got: ", string(got))
	}

	buf3 := new(strings.Builder)
	buf3.Write(testBytes)
	got = toBytes(buf3)
	if !bytes.Equal(got, testBytes) {
		t.Fatal("TestToBytes failed, expected: ", string(testBytes), ", got: ", string(got))
	}

	var testInt = 1
	var testIntBytes = []byte{49}
	if !bytes.Equal(toBytes(testInt), testIntBytes) {
		t.Fatal("TestToBytes failed, expected: ", string(testIntBytes), ", got: ", toBytes(testInt))
	}
}
