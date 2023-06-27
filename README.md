# yubikey
Go lib to validate Yubikey OTP tokens

# Usage

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
