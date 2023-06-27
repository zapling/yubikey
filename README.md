# yubikey
Go lib to validate Yubikey OTP tokens

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
        ClientID: "<clientID>"
    }

    res, err := client.CheckOTP("cccccbenegrnfvfgghcditkerlgvdeifghcrikdebgkt")
    if err != nil {
        // Oh no, something went wrong
        return
    }

    // The the unique ID of the key
    // Map this to your user
    identify := res.GetIdentify() // cccccbenegrn
}

```

# TODO

- Verify Yubico SSL certificate?
- Sign request with `HMAC-SHA-1`
  - https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html
