package yubikey

// Helpful docs
// https://developers.yubico.com/OTP/OTPs_Explained.html
// https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

var defaultAPIServers = []string{
	"api.yubico.com",
	"api2.yubico.com",
	"api3.yubico.com",
	"api4.yubico.com",
	"api5.yubico.com",
}

var ErrWrongOTPLength = errors.New("otp length is wrong, should always be 44")
var ErrTimeout = errors.New("timeout, no API server responded in time")
var ErrInvalidHMAC = errors.New("hmac is invalid")

type Client struct {
	HTTPClient *http.Client
	ClientID   string
	SecretKey  string
}

type channelResult struct {
	StatusCode int
	Body       []byte
	Err        error
}

// https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html
func (c *Client) CheckOTP(otp string) (*OTPResponse, error) {
	if len(otp) != 44 {
		return nil, ErrWrongOTPLength
	}

	nonce := randomString(40)

	// send request to each server, use the result of the first one to respond
	channel := make(chan channelResult)
	for _, apiServer := range defaultAPIServers {
		go c.performRequest(channel, apiServer, otp, nonce)
	}

	select {
	case res := <-channel:
		if res.Err != nil {
			// TODO: do something with error here?
			return nil, fmt.Errorf("err: %w", res.Err)
		}

		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("status '%d', body: %s", res.StatusCode, string(res.Body))
		}

		var otpToken OTPResponse

		if err := otpToken.Parse(res.Body, c.SecretKey); err != nil {
			return nil, fmt.Errorf("failed to parse otp response: %w", err)
		}

		if otp != otpToken.OTP {
			return &otpToken, fmt.Errorf("otp missmatch, '%s' != '%s', body: %s", otp, otpToken.OTP, string(res.Body))
		}

		if nonce != otpToken.Nonce {
			return &otpToken, fmt.Errorf("nonce missmatch, did someone try and spoof the request?")
		}

		return &otpToken, nil
	case <-time.After(5 * time.Second):
		return nil, ErrTimeout
	}
}

func (c *Client) performRequest(ch chan channelResult, apiServer, otp, nonce string) {
	req, err := http.NewRequest("GET", "https://"+apiServer+"/wsapi/2.0/verify", nil)
	if err != nil {
		ch <- channelResult{Err: fmt.Errorf("failed to create request: %w", err)}
		return
	}

	query := req.URL.Query()
	query.Add("id", c.ClientID)
	query.Add("otp", otp)
	query.Add("nonce", nonce)

	if c.SecretKey != "" {
		secretKey, err := base64.StdEncoding.DecodeString(c.SecretKey)
		if err != nil {
			ch <- channelResult{Err: fmt.Errorf("failed to base64 decode secret key: %w", err)}
			return
		}

		data := fmt.Sprintf("id=%s&nonce=%s&otp=%s", c.ClientID, nonce, otp)
		digest := hmac.New(sha1.New, []byte(secretKey))
		_, err = digest.Write([]byte(data))
		if err != nil {
			ch <- channelResult{Err: fmt.Errorf("failed to sign request: %w", err)}
			return
		}

		signature := base64.StdEncoding.EncodeToString(digest.Sum(nil))
		query.Add("h", signature)
	}

	req.URL.RawQuery = query.Encode()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		ch <- channelResult{Err: fmt.Errorf("failed to perform request: %w", err)}
		return
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		ch <- channelResult{
			StatusCode: res.StatusCode,
			Body:       nil,
			Err:        fmt.Errorf("failed to read body: %w", err),
		}
		return
	}

	ch <- channelResult{StatusCode: res.StatusCode, Body: body, Err: nil}
}

var characterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// randomString generates a random string of n length
func randomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = characterRunes[rand.Intn(len(characterRunes))]
	}
	return string(b)
}

type OTPResponse struct {
	OTP    string // The OTP from the YubiKey, from request
	Nonce  string // Random unique data, from request
	H      string // Base64 encoded HMAC-SHA-1, from request
	T      string // Timestamp in UTC
	Status string // The status of the operation
	raw    string // The raw response from the YubiCo server
}

func (v *OTPResponse) Parse(content []byte, secretKey string) error {
	if len(content) == 0 {
		return fmt.Errorf("no content")
	}

	rawStrContent := string(content)
	strContent := strings.ReplaceAll(rawStrContent, "\r", "")

	v.raw = rawStrContent
	rows := strings.Split(strContent, "\n")
	for _, row := range rows {
		sepIndex := strings.IndexRune(row, '=')
		if sepIndex == -1 {
			continue
		}

		key := row[:sepIndex]
		value := row[sepIndex+1:]

		switch key {
		// TODO: add more
		case "otp":
			v.OTP = value
		case "nonce":
			v.Nonce = value
		case "h":
			v.H = value
		case "t":
			v.T = value
		case "status":
			v.Status = value
		}
	}

	if secretKey != "" {
		secretKey, err := base64.StdEncoding.DecodeString(secretKey)
		if err != nil {
			return fmt.Errorf("failed to base64 decode secret key: %w", err)
		}

		data := fmt.Sprintf("nonce=%s&otp=%s&status=%s&t=%s", v.Nonce, v.OTP, v.Status, v.T)
		digest := hmac.New(sha1.New, []byte(secretKey))
		_, err = digest.Write([]byte(data))
		if err != nil {
			return fmt.Errorf("failed to sign response data: %w", err)
		}

		signature := base64.StdEncoding.EncodeToString(digest.Sum(nil))

		if signature != v.H {
			return ErrInvalidHMAC
		}
	}

	return nil
}

// GetIdentity returns the first 12 characters that represent the
// Public ID of the yubikey.
func (v *OTPResponse) GetIdentity() string {
	if len(v.OTP) < 12 {
		return ""
	}

	return v.OTP[:12]
}

// IsValid checks if the OTP token is valid
func (v *OTPResponse) IsValid() bool {
	return v.Status == "OK"
}
