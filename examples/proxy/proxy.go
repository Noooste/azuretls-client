package main

import (
	"fmt"
	"github.com/Noooste/azuretls-client"
)

func main() {
	session := azuretls.NewSession()
	defer session.Close()

	if err := session.SetProxy("http://username:password@ip:port"); err != nil {
		panic(fmt.Sprintf("failed to set proxy: %v", err))
	}

	response, err := session.Get("https://api.ipify.org")

	if err != nil {
		panic(err)
	}

	fmt.Println(response.StatusCode)
	fmt.Println(string(response.Body))
}
