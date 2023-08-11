package main

import (
	"fmt"
	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
)

func main() {
	session := azuretls.NewSession()

	session.Headers = http.Header{
		"user-agent":   {"test"},
		"content-type": {"application/json"},
		"accept":       {"application/json"},
	}

	session.HeadersOrder = azuretls.HeaderOrder{
		"user-agent",
		"content-type",
		"accept",
	}

	response, err := session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		panic(err)
	}

	fmt.Println(response.StatusCode)
	fmt.Println(string(response.Body))

	session.Close()

	// Second way
	session = azuretls.NewSession()

	session.OrderedHeaders = azuretls.OrderedHeaders{
		{"user-agent", "test"},
		{"content-type", "application/json"},
		{"accept", "application/json"},
	}

	response, err = session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		panic(err)
	}

	fmt.Println(response.StatusCode)
	fmt.Println(string(response.Body))

	session.Close()
}
