package main

import (
	"fmt"
	"github.com/Noooste/azuretls-go"
)

func main() {
	session := azuretls.NewSession()

	http2 := "1:65536,2:0,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p"

	if err := session.ApplyHTTP2(http2); err != nil {
		panic(err)
	}

	resp, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		panic(err)
	}

	fmt.Println(resp.StatusCode)
	fmt.Println(string(resp.Body))
}
