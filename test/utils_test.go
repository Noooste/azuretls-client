package azuretls_test

import (
	"bytes"
	"github.com/Noooste/azuretls-client"
	"strings"
	"testing"
)

func TestToBytes(t *testing.T) {
	var testString = "test"
	var testBytes = []byte(testString)

	if !bytes.Equal(azuretls.ToBytes(testString), testBytes) {
		t.Fatal("TestToBytes failed, expected: ", testBytes, ", got: ", azuretls.ToBytes(testString))
	}

	buf := new(bytes.Buffer)
	buf.Write(testBytes)
	got := azuretls.ToBytes(buf)
	if !bytes.Equal(got, testBytes) {
		t.Fatal("TestToBytes failed, expected: ", string(testBytes), ", got: ", string(got))
	}

	buf2 := bytes.Buffer{}
	buf2.Write(testBytes)
	got = azuretls.ToBytes(buf2)
	if !bytes.Equal(got, testBytes) {
		t.Fatal("TestToBytes failed, expected: ", string(testBytes), ", got: ", string(got))
	}

	buf3 := new(strings.Builder)
	buf3.Write(testBytes)
	got = azuretls.ToBytes(buf3)
	if !bytes.Equal(got, testBytes) {
		t.Fatal("TestToBytes failed, expected: ", string(testBytes), ", got: ", string(got))
	}

	buf4 := strings.Builder{}
	buf4.Write(testBytes)
	got = azuretls.ToBytes(buf4)
	if !bytes.Equal(got, testBytes) {
		t.Fatal("TestToBytes failed, expected: ", string(testBytes), ", got: ", string(got))
	}

	buf5 := append([]byte{}, testBytes...)
	got = azuretls.ToBytes(buf5)
	if !bytes.Equal(got, testBytes) {
		t.Fatal("TestToBytes failed, expected: ", string(testBytes), ", got: ", string(got))
	}

	var testInt = 1
	var testIntBytes = []byte{49}
	if !bytes.Equal(azuretls.ToBytes(testInt), testIntBytes) {
		t.Fatal("TestToBytes failed, expected: ", string(testIntBytes), ", got: ", azuretls.ToBytes(testInt))
	}
}

func TestToReader(t *testing.T) {
	var testString = "test"
	var testBytes = []byte(testString)

	if !bytes.Equal(azuretls.ToBytes(testString), testBytes) {
		t.Fatal("TestToReader failed, expected: ", testBytes, ", got: ", azuretls.ToBytes(testString))
	}

	buf := new(bytes.Buffer)
	buf.Write(testBytes)
	reader, err := azuretls.ToReader(buf)
	if err != nil {
		t.Fatal("TestToReader failed")
	}

	if !bytes.Equal(azuretls.ToBytes(reader), testBytes) {
		t.Fatal("TestToReader failed")
	}

	buf2 := bytes.Buffer{}
	buf2.Write(testBytes)
	reader, err = azuretls.ToReader(buf2)
	if err != nil {
		t.Fatal("TestToReader failed")
	}

	if !bytes.Equal(azuretls.ToBytes(reader), testBytes) {
		t.Fatal("TestToReader failed")
	}

	buf3 := new(strings.Builder)
	buf3.Write(testBytes)
	reader, err = azuretls.ToReader(buf3)
	if err != nil {
		t.Fatal("TestToReader failed")
	}

	if !bytes.Equal(azuretls.ToBytes(reader), testBytes) {
		t.Fatal("TestToReader failed")
	}

	buf4 := strings.Builder{}
	buf4.Write(testBytes)
	reader, err = azuretls.ToReader(buf4)
	if err != nil {
		t.Fatal("TestToReader failed")
	}

	if !bytes.Equal(azuretls.ToBytes(reader), testBytes) {
		t.Fatal("TestToReader failed")
	}

	buf5 := append([]byte{}, testBytes...)
	reader, err = azuretls.ToReader(buf5)
	if err != nil {
		t.Fatal("TestToReader failed")
	}

	if !bytes.Equal(azuretls.ToBytes(reader), testBytes) {
		t.Fatal("TestToReader failed")
	}
}

func TestUrlEncode(t *testing.T) {
	type Foo struct {
		Bar string `url:"bar"`
		Baz string `url:"baz"`
	}

	var f = Foo{
		Bar: "bar",
		Baz: "baz baz baz",
	}

	var testString = "bar=bar&baz=baz+baz+baz"
	var otherTestString = "baz=baz+baz+baz&bar=bar"

	if azuretls.UrlEncode(f) != testString {
		t.Fatal("TestUrlEncode failed, expected: ", testString, ", got: ", azuretls.UrlEncode(f))
	}

	var FooMap = map[string]string{
		"bar": "bar",
		"baz": "baz baz baz",
	}

	encoded := azuretls.UrlEncode(FooMap)
	if encoded != testString && encoded != otherTestString {
		t.Fatal("TestUrlEncode failed, expected: ", testString, ", got: ", encoded)
	}

	var FooString = "baz baz baz baz"
	if azuretls.UrlEncode(FooString) != "baz+baz+baz+baz" {
		t.Fatal("TestUrlEncode failed, expected: baz+baz+baz+baz, got: ", azuretls.UrlEncode(FooString))
	}
}

type q struct {
	A int    `url:"a"`
	B string `url:"b"`
	C string `url:"c,omitempty"`
}

func TestQuery2(t *testing.T) {
	dumped := azuretls.UrlEncode(q{
		A: 1,
		B: "b",
	})
	if dumped != "a=1&b=b" {
		t.Error("UrlEncode() failed, expected a=1&b=b, got", dumped)
	}
}
