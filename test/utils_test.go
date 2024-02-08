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

	var testInt = 1
	var testIntBytes = []byte{49}
	if !bytes.Equal(azuretls.ToBytes(testInt), testIntBytes) {
		t.Fatal("TestToBytes failed, expected: ", string(testIntBytes), ", got: ", azuretls.ToBytes(testInt))
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

	if azuretls.UrlEncode(f) != testString {
		t.Fatal("TestUrlEncode failed, expected: ", testString, ", got: ", azuretls.UrlEncode(f))
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
