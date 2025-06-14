package main

import (
	"fmt"
	"github.com/Noooste/azuretls-client"
)

func main() {
	session := azuretls.NewSession()
	defer session.Close()

	http3 := "1:16383;7:100;GREASE|m,s,a,p"

	if err := session.ApplyHTTP3(http3); err != nil {
		panic(fmt.Sprintf("failed to apply HTTP/3 settings: %v", err))
	}

	resp, err := session.Do(&azuretls.Request{
		Method:     "GET",
		Url:        "https://fp.impersonate.pro/api/http3",
		ForceHTTP3: true,
	})

	if err != nil {
		panic(err)
	}

	fmt.Println(resp.StatusCode)
	fmt.Println(string(resp.Body))
}
