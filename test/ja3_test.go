package azuretls_test

import (
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/Noooste/azuretls-client"
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
	session := azuretls.NewSession()

	var ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-27-0-51-65037-23-5-35-11-13-10-16-18-43-45-17613,29-23-24,0"
	if err := session.ApplyJa3(ja3, azuretls.Chrome); err != nil {
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

	ref := strings.Split(ja3, ",")

	actual := strings.Split(loaded["tls"].(map[string]any)["ja3"].(string), ",")

	if len(actual) != 5 {
		t.Fatal("Expected 4 parts, got ", len(actual))
		return
	}

	if actual[0] != ref[0] {
		t.Fatal("Expected "+ref[0]+", got ", actual[0])
		return
	}

	if actual[1] != ref[1] {
		t.Fatal("Expected "+ref[1]+", got ", actual[1])
		return
	}

	if actual[2] != ref[2] && strings.TrimSuffix(ref[2], "-21") != strings.TrimSuffix(ref[2], "-21") {
		t.Fatal("Expected "+ref[2]+", got ", actual[2])
		return
	}

	if actual[3] != ref[3] {
		t.Fatal("Expected "+ref[3]+", got ", actual[3])
		return
	}

	if actual[4] != ref[4] {
		t.Fatal("Expected "+ref[4]+", got ", actual[4])
		return
	}
}

func TestFirefox(t *testing.T) {
	session := azuretls.NewSession()

	var ja3 = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0"
	if err := session.ApplyJa3(ja3, azuretls.Firefox); err != nil {
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

	ref := strings.Split(ja3, ",")

	actual := strings.Split(loaded["tls"].(map[string]any)["ja3"].(string), ",")

	if len(actual) != 5 {
		t.Fatal("Expected 4 parts, got ", len(actual))
		return
	}

	if actual[0] != ref[0] {
		t.Fatal("Expected "+ref[0]+", got ", actual[0])
		return
	}

	if actual[1] != ref[1] {
		t.Fatal("Expected "+ref[1]+", got ", actual[1])
		return
	}

	if actual[2] != ref[2] {
		t.Fatal("Expected "+ref[2]+", got ", actual[2])
		return
	}

	if actual[3] != ref[3] {
		t.Fatal("Expected "+ref[3]+", got ", actual[3])
		return
	}

	if actual[4] != ref[4] {
		t.Fatal("Expected "+ref[4]+", got ", actual[4])
		return
	}
}

func TestSession_ApplyJa3(t *testing.T) {
	session := azuretls.NewSession()

	ja3Origin := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-13-10-11-17613-43-45-35-65037-5-51-65281-16-18-0-27-21,29-23-24,0"

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
	if err = response.JSON(&loaded); err != nil {
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
	applyWrongJA3(t, session, ",4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17613-21,29-23-24,0", azuretls.Chrome)
	applyWrongJA3(t, session, "771,,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17613-21,29-23-24,0", azuretls.Chrome)
	applyWrongJA3(t, session, "a-771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17613-21,29-23-24,0", azuretls.Safari)
	applyWrongJA3(t, session, "771,a-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17613-21,29-23-24,0", azuretls.Safari)
	applyWrongJA3(t, session, "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,a-45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17613-21,29-23-24,0", azuretls.Safari)
	applyWrongJA3(t, session, "771,a-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17613-21,a-29-23-24,0", azuretls.Safari)
	applyWrongJA3(t, session, "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17613-21,29-23-24,a-0", azuretls.Safari)

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

func TestECH(t *testing.T) {
	session := azuretls.NewSession()

	if err := session.ApplyJa3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65037-45-13-18-35-23-5-65281-27-10-16-11-43-51-17613-0-21,29-23-24,0", azuretls.Chrome); err != nil {
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

func test(wg *sync.WaitGroup) {
	defer wg.Done()
	for i := 0; i < 1e3; i++ {
		azuretls.GetLastChromeVersion()
	}
}

func TestGetLastChromeVersion(t *testing.T) {
	var (
		wg = new(sync.WaitGroup)
	)

	for i := 0; i < 1e3; i++ {
		wg.Add(1)
		go test(wg)
	}

	wg.Wait()
}

func TestGetMondialRelay(t *testing.T) {
	t.SkipNow()

	session := azuretls.NewSession()
	defer session.Close()

	if err := session.SetProxy(os.Getenv("NON_SECURE_PROXY")); err != nil {
		t.Fatal(err)
	}

	resp, err := session.Get("https://www.mondialrelay.fr/suivi-de-colis/")

	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 200 {
		t.Fatal("Expected 200")
	}
}

func TestFirefoxProfile(t *testing.T) {
	session := azuretls.NewSession()

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	var loaded map[string]any
	if err = response.JSON(&loaded); err != nil {
		t.Fatal(err)
	}

	hash := loaded["tls"].(map[string]any)["peetprint_hash"].(string)

	if hash == "" {
		t.Fatal("Expected hash")
	}

	session.Close()

	session = azuretls.NewSession()
	session.Browser = azuretls.Firefox

	response, err = session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if err = response.JSON(&loaded); err != nil {
		t.Fatal(err)
	}

	fHash := loaded["tls"].(map[string]any)["peetprint_hash"].(string)

	if fHash == "" {
		t.Fatal("Expected hash")
	}

	if fHash == hash {
		t.Fatal("Expected different hashes")
	}
}

func TestIosProfile(t *testing.T) {
	session := azuretls.NewSession()

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	var loaded map[string]any
	if err = response.JSON(&loaded); err != nil {
		t.Fatal(err)
	}

	hash := loaded["tls"].(map[string]any)["peetprint_hash"].(string)

	if hash == "" {
		t.Fatal("Expected hash")
	}

	session.Close()

	session = azuretls.NewSession()
	session.Browser = azuretls.Ios

	response, err = session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if err = response.JSON(&loaded); err != nil {
		t.Fatal(err)
	}

	fHash := loaded["tls"].(map[string]any)["peetprint_hash"].(string)

	if fHash == "" {
		t.Fatal("Expected hash")
	}

	if fHash == hash {
		t.Fatal("Expected different hashes")
	}
}

func TestGetApplyJa3WithoutSpecifications(t *testing.T) {
	session := azuretls.NewSession()
	defer session.Close()

	err := session.ApplyJa3WithSpecifications("771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0", &azuretls.TlsSpecifications{}, azuretls.Firefox)
	if err != nil {
		t.Fatal(err)
		return
	}

	err = session.ApplyJa3WithSpecifications("771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0", &azuretls.TlsSpecifications{}, azuretls.Chrome)
	if err != nil {
		t.Fatal(err)
		return
	}
}
