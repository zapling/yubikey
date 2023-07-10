# yubikey
Go lib to validate Yubikey OTP tokens against YubiCo servers

# Usage

Retrieve your ClientID and Secret key from YubiCo [here](https://upgrade.yubico.com/getapikey/) (Yubikey required).

```go

import (
    "net/http"
    "github.com/zapling/yubikey"
)

func main() {
    client := yubikey.Client{
        HTTPClient: http.DefaultClient,
        ClientID: "<clientID>",
        SecretKey: "<secretKey>", // optional, HMAC signing of the request data will be done
    }

    res, err := client.CheckOTP("cccccbenegrnfvfgghcditkerlgvdeifghcrikdebgkt")
    if err != nil {
        // Oh no, something went wrong
        return
    }

    if !res.IsValid() {
        // Token is not valid
        return
    }

    // The the unique ID of the key
    // Map this to your user
    identify := res.GetIdentify() // cccccbenegrn
}

```

# TODO

- Verify Yubico SSL certificate?
