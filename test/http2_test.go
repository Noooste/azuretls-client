package azuretls_test

import (
	"encoding/json"
	"github.com/Noooste/azuretls-client"
	"testing"
)

func TestSession_ApplyAkamaiFingerprintChrome(t *testing.T) {

	session := azuretls.NewSession()

	expectedAf := "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,s,a,p"

	if err := session.ApplyHTTP2(expectedAf); err != nil {
		t.Fatal(err)
	}

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("Expected 200")
	}

	var loaded map[string]any

	err = json.Unmarshal(response.Body, &loaded)

	if err != nil {
		t.Fatal(err)
	}

	af := loaded["http2"].(map[string]any)["akamai_fingerprint"].(string)

	if af != expectedAf {
		t.Fatal("Expected "+expectedAf+", got ", af)
	}
}

func TestSession_ApplyAkamaiFingerprintFirefox(t *testing.T) {

	session := azuretls.NewSession()
	expectedAf := "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s"

	if err := session.ApplyHTTP2(expectedAf); err != nil {
		t.Fatal(err)
	}

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("Expected 200")
	}

	var loaded map[string]any

	err = json.Unmarshal(response.Body, &loaded)

	if err != nil {
		t.Fatal(err)
	}

	af := loaded["http2"].(map[string]any)["akamai_fingerprint"].(string)

	if af != expectedAf {
		t.Fatal("Expected "+expectedAf+", got ", af)
	}
}

func TestIos(t *testing.T) {
	session := azuretls.NewSession()
	session.Browser = azuretls.Ios
	expected := "1:4096;3:100;4:2097152;5:16384;6:4294967295|15663105|0|m,s,p,a"

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("Expected 200")
	}

	var loaded map[string]any

	err = json.Unmarshal(response.Body, &loaded)

	if err != nil {
		t.Fatal(err)
	}

	af := loaded["http2"].(map[string]any)["akamai_fingerprint"].(string)

	if af != expected {
		t.Fatal("Expected "+expected+", got ", af)
	}
}

func applyBadHTTP2(t *testing.T, s *azuretls.Session, fp string) {
	if err := s.ApplyHTTP2(fp); err == nil {
		t.Fatal("Expected error on fingerprint: ", fp)
	}
}

func TestWrongFp(t *testing.T) {
	session := azuretls.NewSession()
	applyBadHTTP2(t, session, "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,v")
	applyBadHTTP2(t, session, "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p,v")
	applyBadHTTP2(t, session, "1,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p")
	applyBadHTTP2(t, session, "1:a,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p")
	applyBadHTTP2(t, session, "a:1,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p")
	applyBadHTTP2(t, session, "a:1,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p")
	applyBadHTTP2(t, session, "a:1,2:0,3:1000,4:6291456,6:262144|a|0|m,s,a,p")
	applyBadHTTP2(t, session, "a:1,2:0,3:1000,4:6291456,6:262144|0|a|m,s,a,p")
	applyBadHTTP2(t, session, "0|0|a|m,s,a,p")
	applyBadHTTP2(t, session, "0|0|1:2::|m,s,a,p")
	applyBadHTTP2(t, session, "0|0|a:2:3:4|m,s,a,p")
	applyBadHTTP2(t, session, "0|0|1:a:3:4|m,s,a,p")
	applyBadHTTP2(t, session, "0|0|1:2:a:4|m,s,a,p")
	applyBadHTTP2(t, session, "0|0|1:2:3:a|m,s,a,p")
}
