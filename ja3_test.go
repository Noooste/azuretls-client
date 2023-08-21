package azuretls

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestChrome(t *testing.T) {
	// Chrome 80

	session := NewSession()

	if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,0", Chrome); err != nil {
		t.Fatal(err)
	}

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("Expected 200")
		return
	}

	var loaded map[string]any

	err = json.Unmarshal(response.Body, &loaded)

	if err != nil {
		t.Fatal(err)
	}

	ja3 := loaded["tls"].(map[string]any)["ja3"].(string)
	split := strings.Split(ja3, ",")

	if len(split) != 5 {
		t.Fatal("Expected 4 parts, got ", len(split))
		return
	}

	version := "771"
	if split[0] != version {
		t.Fatal("Expected "+version+", got ", split[0])
		return
	}

	ciphers := "4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53"
	if split[1] != ciphers {
		t.Fatal("Expected "+ciphers+", got ", split[1])
		return
	}

	//since chrome shuffle extension = not relevant to check the order
	extensions := "45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21"
	nbExtensions := strings.Count(extensions, "-") + 1

	if nbExtensions != strings.Count(split[2], "-")+1 {
		t.Fatal("Expected "+extensions+", got ", split[2])
		return
	}

	ellipticCurves := "29-23-24"
	if split[3] != ellipticCurves {
		t.Fatal("Expected"+ellipticCurves+", got ", split[3])
		return
	}

	if split[4] != "0" {
		t.Fatal("Expected 0, got ", split[4])
		return
	}
}

func TestSession_ApplyJa3(t *testing.T) {

	session := NewSession()

	ja3Origin := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24-25-26,0"

	if err := session.ApplyJa3(ja3Origin, Chrome); err != nil {
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

	ja3 := loaded["tls"].(map[string]any)["ja3"].(string)
	split := strings.Split(ja3, ",")
	splitOrigin := strings.Split(ja3Origin, ",")

	if len(split) != 5 {
		t.Fatal("Expected 4 parts, got ", len(split))
	}

	if split[0] != splitOrigin[0] {
		t.Fatal("Expected "+splitOrigin[0]+", got ", split[0])
	}

	if split[1] != splitOrigin[1] {
		t.Fatal("Expected "+splitOrigin[1]+", got ", split[1])
	}

	if split[2] != splitOrigin[2] {
		t.Fatal("Expected "+splitOrigin[2]+", got ", split[2])
	}

	if split[3] != splitOrigin[3] {
		t.Fatal("Expected "+splitOrigin[3]+", got ", split[3])
	}

	if split[4] != splitOrigin[4] {
		t.Fatal("Expected "+splitOrigin[4]+", got ", split[4])
	}
}

func TestSession_ApplyJa32(t *testing.T) {
	session := NewSession()

	if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-49-28-34-41-22-17-50-45-16-65281-51-18-11-27-35-23-10-5-17513-13172-21,29-23-24,0", Chrome); err != nil {
		t.Fatal(err)
	}

	if err := session.ApplyJa3("70,0,0,0,0,0", Chrome); err == nil {
		t.Fatal("Expected error")
	}

	if err := session.ApplyJa3(",4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,0", Chrome); err == nil {
		t.Fatal("Expected error")
	}

	if err := session.ApplyJa3("771,,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,0", Chrome); err == nil {
		t.Fatal("Expected error")
	}

	if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,,29-23-24,0", Chrome); err == nil {
		t.Fatal("Expected error")
	}

	if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-49-28-34-41-22-17-50-45-16-65281-51-18-11-27-35-23-10-5-17513-13172-21,,0", Chrome); err == nil {
		t.Fatal("Expected error")
	}

	if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,", Chrome); err == nil {
		t.Fatal("Expected error")
	}

	if err := session.ApplyJa3("a-771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,0", Safari); err == nil {
		t.Fatal("Expected error")
	}

	if err := session.ApplyJa3("771,a-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,0", Safari); err == nil {
		t.Fatal("Expected error")
	}

	if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,a-45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,0", Safari); err == nil {
		t.Fatal("Expected error")
	}

	if err := session.ApplyJa3("771,a-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,a-29-23-24,0", Safari); err == nil {
		t.Fatal("Expected error")
	}

	if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,a-0", Safari); err == nil {
		t.Fatal("Expected error")
	}
}

func TestGetLastIosVersion(t *testing.T) {

	session := NewSession()

	session.GetClientHelloSpec = GetLastIosVersion

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

	expected := []string{
		"*",
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	}

	tls := loaded["tls"].(map[string]any)
	ciphers := tls["ciphers"].([]any)

	for i, cipher := range ciphers {
		if expected[i] != "*" && expected[i] != cipher {
			t.Fatal("Expected "+expected[i]+", got ", cipher)
		}
	}

	extensions := tls["extensions"].([]any)

	if extensions[6].(map[string]any)["name"] != "application_layer_protocol_negotiation (16)" {
		t.Fatal("Expected application_layer_protocol_negotiation (16), got ", extensions[6].(map[string]any)["name"])
	}
}

func TestGetSupportedAlgorithms(t *testing.T) {
	var navigators = []string{
		Chrome,
		Firefox,
		Opera,
		Safari,
	}

	for _, navigator := range navigators {
		getSupportedAlgorithms(navigator)
	}
}

func TestGetSupportedVersion(t *testing.T) {
	var navigators = []string{
		Chrome,
		Firefox,
		Opera,
		Safari,
	}

	for _, navigator := range navigators {
		getSupportedVersion(navigator)
	}
}
