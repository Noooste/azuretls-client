package azuretls_test

import (
	"encoding/json"
	"fmt"
	"github.com/Noooste/azuretls-client"
	"log"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	session := azuretls.NewSession()

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != 200 {
		t.Fatal("Expected 200")
	}
}

func TestChrome(t *testing.T) {
	// Chrome 80

	session := azuretls.NewSession()

	if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,0", azuretls.Chrome); err != nil {
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

	response.MustJSON(&loaded)

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
	session := azuretls.NewSession()

	ja3Origin := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-13-10-11-17513-43-45-35-65037-5-51-65281-16-18-0-27-21,29-23-24,0"

	if err := session.ApplyJa3(ja3Origin, azuretls.Chrome); err != nil {
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

	if split[2] != splitOrigin[2] && strings.TrimSuffix(splitOrigin[2], "-21") != split[2] {
		t.Fatal("Expected "+splitOrigin[2]+", got ", split[2])
	}

	if split[3] != splitOrigin[3] {
		t.Fatal("Expected "+splitOrigin[3]+", got ", split[3])
	}

	if split[4] != splitOrigin[4] {
		t.Fatal("Expected "+splitOrigin[4]+", got ", split[4])
	}
}

func applyWrongJA3(t *testing.T, s *azuretls.Session, ja3 string, navigator string) {
	if err := s.ApplyJa3(ja3, navigator); err == nil {
		t.Fatal("Expected error on ja3: " + ja3 + " with navigator: " + navigator)
	}
}

func TestSession_ApplyJa32(t *testing.T) {
	session := azuretls.NewSession()
	applyWrongJA3(t, session, "70,0,0,0,0,0", azuretls.Chrome)
	applyWrongJA3(t, session, ",4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,0", azuretls.Chrome)
	applyWrongJA3(t, session, "771,,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,0", azuretls.Chrome)
	applyWrongJA3(t, session, "a-771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,0", azuretls.Safari)
	applyWrongJA3(t, session, "771,a-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,0", azuretls.Safari)
	applyWrongJA3(t, session, "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,a-45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,0", azuretls.Safari)
	applyWrongJA3(t, session, "771,a-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,a-29-23-24,0", azuretls.Safari)
	applyWrongJA3(t, session, "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24,a-0", azuretls.Safari)

	if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,,29-23-24,0", azuretls.Firefox); err != nil {
		t.Fatal(err)
	}

	if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,,,0", azuretls.Firefox); err != nil {
		t.Fatal(err)
	}

	if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,,,", azuretls.Firefox); err != nil {
		t.Fatal(err)
	}
}

func TestGetLastIosVersion(t *testing.T) {
	session := azuretls.NewSession()

	session.GetClientHelloSpec = azuretls.GetLastIosVersion

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

func TestECH(t *testing.T) {
	session := azuretls.NewSession()

	if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65037-45-13-18-35-23-5-65281-27-10-16-11-43-51-17513-0-21,29-23-24,0", azuretls.Chrome); err != nil {
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
}

func TestJa3(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	err := session.ApplyJa3("771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0", azuretls.Firefox)
	if err != nil {
		log.Fatal(err)
		return
	}

	err = session.ApplyHTTP2("1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s")
	if err != nil {
		log.Fatal(err)
		return
	}

	response, err := session.Get("https://www.cloudflare.com/cdn-cgi/trace")

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(response.StatusCode, string(response.Body))
	}
}
