package azuretls_test

import (
	"fmt"
	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"
	"io"
	"testing"
)

func TestResponse_CloseBody(t *testing.T) {
	session := azuretls.NewSession()

	response, err := session.Do(&azuretls.Request{
		Method:     "GET",
		Url:        "https://tls.peet.ws/api/all",
		IgnoreBody: true,
	})

	if err != nil {
		t.Fatal(err)
	}

	if _, err = io.ReadAll(response.RawBody); err != nil {
		t.Fatal("TestResponse_CloseBody failed, expected: nil, got: ", err)
	}

	if err = response.CloseBody(); err != nil {
		t.Fatal("TestResponse_CloseBody failed, expected: nil, got: ", err)
	}
}

func TestResponse_Load(t *testing.T) {
	session := azuretls.NewSession()

	var response, err = session.Do(&azuretls.Request{
		Method:     http.MethodGet,
		Url:        "https://tls.peet.ws/api/all",
		IgnoreBody: true,
	})

	if err != nil {
		t.Fatal(err)
	}

	var loaded map[string]interface{}

	if err = response.JSON(&loaded); err == nil {
		t.Fatal("TestResponse_Load failed, expected: err, got: ", nil)
	}

	session.Close()

	response, err = session.Get("https://tls.peet.ws/api/all")

	if err != nil {
		t.Fatal(err)
	}

	if err = response.JSON(&loaded); err != nil {
		t.Fatal("TestResponse_Load failed, expected: nil, got: ", err)
	}
}

func TestSessionPaypal(t *testing.T) {
	session := azuretls.NewSession()

	headers := azuretls.OrderedHeaders{
		{"Sec-Ch-Ua", "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\""},
		{"Sec-Ch-Ua-Mobile", "?0"},
		{"Sec-Ch-Ua-Platform", "\"Windows\""},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"Accept-Language", "de-DE,de;q=0.9"},
		{"Cache-Control", "max-age=0"},
		{"Connection", "keep-alive"},
		{"Content-Type", "application/x-www-form-urlencoded"},
		{"Cookie", "JSESSIONID=1A9596F9CB1F23CC4848E87ACD3C7337.live112e"},
		{"Host", "live.adyen.com"},
		{"Origin", "https://live.adyen.com"},
		{"Referer", "https://live.adyen.com/hpp/checkout.shtml?p=eJytVltz6jgM-jXw0gmTOJeShzzQQFu2lLZc2tO*MCZWLiWJc2wDw-n1qyTAsin0nNnZGcC29NmSP8kSyyRNkzzqMSZAyk6QqJ3Xm7KQybC9bOj4Oldi5-UHTU3M1xLG62wJ4kmMaQZe3iK3tAkruFQ09TkDz3It3WrqpRIAyhtmVzOQ6nN1ZZAGZLYrwEOhoDmrzinorqBpO5gJGkBBBeTK03XNBcMG1zagG4ZsSViX2UGXBWaom45udgON2kaXmaGxDMFyluBqutEOYghWfK066v84rCarchIJC9YCjwvq9WA*aTNIkw2I3Vnivyj-Yb6pukR9E-eF*ybgHPkNzJ79DEQQ01z1gsovzxc8kOjaQT7MFUSCqoTnHVVu8e8H-sPTfLa4G4wHk6F-Fol2JI6ebR7VEwihZA083b7uXhuO65*YmYBai7xPFfX8lxfiTO-t5zfrfuafnDBNIs81P-s7dSeQFmPFProSJ73rwJTxw-sI5-gh89ufvc-8x1vwkfWcm0HL7Ld5AXmSb3gSAEMbHcxCMDpf4ngexkAGIinKi3n3kKb86iFRanflp1TKJMCRRxe2JhmNYC5SL1aqkC2zV7uYAUtoJyipxnTIUFIBy8uohYoxAXKapLgKF3StOE4Kwdk6UCWC6K5ldheGri96oxkOKKuO0uLSOW1VOqcFtXM48kjbxokCDUkUmbZJYHvJWwVZL6vSwHFd9xvUkHm1Gxra1x4N-Q0T7DL8lar9ufr3qGcMNT5U5OIiMq*fRzjEHdIzLqD2fH2lfrvd7olnUPKK30u0HbnuxCpLW*ZtkDBMJrzxBaMbqnyKj4Dj6x7zHM7CyJ*lHflX2k3jpCiwcl6AngTuvG-kELWb3nToL6b3w*fn4fjuG*zvQkb*OGTkj0JGfs-e4ZgRwiWWLmwXGVo*zVgBBVCl8VxTSQZY-r2QphJQLueTUSMVDi1CxrwoQGhleexQtoN8-ygbAJRIEBt0p3yGz7X1YY5YjMwEn7SAQKFmY*BPygOa7jGPoGKOqXPbKLaYTPty2yKOqCogeonS2k9il57apa92M3FRwPNqYJBh-9xig8Oqz0Wtm2JwpFbBFwy0crkHL0pjOOuV99QOXk*OxtHoLRcMRM7Lef*kWJf7nMqtflbZtkn4*Dr-cfMUfuyXPnmXxl*cPG5-ylq0tB37bkkfVr*WE-PX58vIsiqFyfDOp50er-1f27PEdoav5JWmCSs7L9GJpekEVTOiY7h1t-wxPtr7QHbCREhV9dc*NqpIHhUR5Hh1bz5*GD*9jY9iLAo1nNGIyegoV5BCEWOu1j3ba5EbyzXsa9N2LHJADTKs5V4oGW4No5alY6GPMIgHfdk3kYbqnQ8wmcokOSpHZRqh3TJuB9m*c8tVktd-m9bLzoZ0LMOw9S5xug76QAwsR*58*-DhD4zJuutor*lOcPqqR9bOGI9u5Mhx30k4*sx2KeV-A01hkMM&u=redirectPayPal"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "same-origin"},
		{"Upgrade-Insecure-Requests", "1"},
		{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"},
	}

	response, err := session.Post("https://live.adyen.com/hpp/redirectPayPal.shtml?", `openinvoicedata.numberOfLines=2&openinvoicedata.line2.itemAmount=0&shopperType=2&openinvoicedata.line2.itemVatPercentage=0&sessionValidity=2024-02-01T20%3A09%3A01Z&openinvoicedata.line2.numberOfItems=1&openinvoicedata.line2.itemVatAmount=0&shopper.firstName=Dersgs&shopper.gender=UNKNOWN&openinvoicedata.line1.itemId=209438-100-M10W12&billingAddress.country=DE&openinvoicedata.line1.currencyCode=EUR&brandCode=paypal&checkout.traceparent=00-9e15e951e8ffdb2d8d5c8dc3f036038c-a518d3f1bfe46be9-01&deliveryAddress.street=Im+Testjk+12&openinvoicedata.line1.itemVatAmount=0&shopperEmail=fsdgdsfg%40gesg.de&skinCode=pub.v2.4115082686491211.v9UwKZCE1Ru86-VlyroaV0g4y1NLBsL69Y2fLjmylao&cTraceparent=00-9e15e951e8ffdb2d8d5c8dc3f036038c-a518d3f1bfe46be9-01&shopper.telephoneNumber=%2B4915735642&openinvoicedata.line2.vatCategory=None&shopperLocale=de_DE&merchantIntegration.type=CHECKOUT_GENERIC&openinvoicedata.line1.vatCategory=None&deliveryAddress.city=ASdfdsf&openinvoicedata.line2.currencyCode=EUR&merchantReturnData=CQQ26SH5PW4HTC53&openinvoicedata.line1.description=Hello+Kitty+Classic+Clog&paymentAmount=6999&openinvoicedata.line2.description=Shipping&merchantSig=93jDytGr%2F1kdZ8s%2FA7c3shKYL%2F%2F2UFqAjnXWcZmA6BE%3D&billingAddress.street=Im+Testjk+12&countryCode=DE&openinvoicedata.line1.itemAmount=6999&billingAddress.city=ASdfdsf&deliveryAddress.country=DE&shopperInteraction=Ecommerce&merchantReference=05787169CDE&resURL=https%3A%2F%2Fcheckoutshopper-live.adyen.com%2Fcheckoutshopper%2Fservices%2FPaymentIncomingRedirect%2Fv1%2FlocalPaymentMethod%3FmerchantAccount%3DCrocsDE%26returnURL%3Dhttps%253A%252F%252Fwww.crocs.de%252Fon%252Fdemandware.store%252FSites-crocs_de-Site%252Fde_DE%252FAdyen-RedirectReturnURL%253Forderno%253D05787169CDE%2526s%253Dmn%25252fMVUXBOfZ%25252fC2Ys1Jo2Mwqs%25252b565GbaKkzbR3zjQL44%25253d%26cTraceparent%3D00-9e15e951e8ffdb2d8d5c8dc3f036038c-a518d3f1bfe46be9-01&openinvoicedata.line1.numberOfItems=1&openinvoicedata.line2.itemId=BASIC_SHIPPING&deliveryAddressType=2&deliveryAddress.postalCode=49404&merchantIntegration.version=53&billingAddress.houseNumberOrName=n%2Fa&repeat-on-timeout=false&billingAddress.postalCode=49404&openinvoicedata.line1.itemVatPercentage=0&shopper.lastName=dagdsg&merchantAccount=CrocsDE&openinvoicedata.line1.imageUrl=https%3A%2F%2Fmedia.crocs.com%2Fimages%2Ft_thumbnail%2Ff_auto%2Fproducts%2F209438_100_ALT100%2Fcrocs-hello-kitty-classic-clog-white-charm-view&deliveryAddress.houseNumberOrName=n%2Fa&openinvoicedata.line1.productUrl=https%3A%2F%2Fwww.crocs.de%2Fp%2Fhello-kitty-classic-clog%2F209438.html%3Fcid%3D100&billingAddressType=2&currencyCode=EUR`, headers)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(response.StatusCode)
}
