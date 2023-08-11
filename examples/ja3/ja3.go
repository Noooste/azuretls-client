package main

import (
	"fmt"
	"github.com/Noooste/azuretls-client"
)

func main() {
	session := azuretls.NewSession()

	// First way
	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-13-43-0-16-65281-51-18-11-27-35-23-10-5-17513-21,29-23-24-25-26,0"
	if err := session.ApplyJa3(ja3, azuretls.Chrome); err != nil {
		panic(err)
	}

	resp, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		panic(err)
	}

	fmt.Println(resp.StatusCode)
	fmt.Println(string(resp.Body))
	session.Close()

	// Second way
	session = azuretls.NewSession()

	session.GetClientHelloSpec = azuretls.GetLastChromeVersion

	resp, err = session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		panic(err)
	}

	fmt.Println(resp.StatusCode)
	fmt.Println(string(resp.Body))
}
