package yubikey

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var otpToken = "cccccbenegrnfvfgghcditkerlgvdeifghcrikdebgkt"

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestCheckOTP(t *testing.T) {
	getClient := func(transport RoundTripFunc) Client {
		httpClient := http.DefaultClient
		httpClient.Transport = transport
		return Client{
			HTTPClient: httpClient,
			ClientID:   "1",
		}
	}

	t.Run("Wrong OTP length", func(t *testing.T) {
		client := Client{}
		_, err := client.CheckOTP(otpToken[:len(otpToken)-1])
		assert.ErrorIs(t, err, ErrWrongOTPLength)
	})

	t.Run("No response from any server", func(t *testing.T) {
		client := getClient(func(r *http.Request) *http.Response {
			time.Sleep(10 * time.Second)
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
			}
		})

		_, err := client.CheckOTP(otpToken)
		assert.ErrorIs(t, err, ErrTimeout)
	})

	t.Run("Should use the first response from any server", func(t *testing.T) {
		client := getClient(func(r *http.Request) *http.Response {
			hostname := r.URL.Hostname()

			if hostname != "api3.yubico.com" {
				time.Sleep(10 * time.Second)
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
				}
			}

			response := fmt.Sprintf(
				"t=%s\notp=%s\nnonce=%s\nstatus=OK",
				time.Now().Format(time.RFC3339),
				r.URL.Query().Get("otp"),
				r.URL.Query().Get("nonce"),
			)

			readCloser := io.NopCloser(bytes.NewBuffer([]byte(response)))

			t.Log("Request for api3.yubico.com")

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       readCloser,
			}
		})

		_, err := client.CheckOTP(otpToken)
		assert.Nil(t, err)
	})

	t.Run("Non 200 OK response", func(t *testing.T) {
		client := getClient(func(r *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
			}
		})

		_, err := client.CheckOTP(otpToken)
		assert.NotNil(t, err)
	})

	t.Run("Non parsable body", func(t *testing.T) {
		client := getClient(func(r *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
			}
		})

		_, err := client.CheckOTP(otpToken)
		assert.NotNil(t, err)
	})

	t.Run("Wrong otp in response body", func(t *testing.T) {
		client := getClient(func(r *http.Request) *http.Response {
			response := fmt.Sprintf(
				"t=%s\notp=%s\nnonce=%s\nstatus=OK",
				time.Now().Format(time.RFC3339),
				otpToken[:len(otpToken)-1],
				r.URL.Query().Get("nonce"),
			)

			readCloser := io.NopCloser(bytes.NewBuffer([]byte(response)))

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       readCloser,
			}
		})

		_, err := client.CheckOTP(otpToken)
		assert.NotNil(t, err)
	})

	t.Run("Wrong nonce in response body", func(t *testing.T) {
		client := getClient(func(r *http.Request) *http.Response {
			response := fmt.Sprintf(
				"t=%s\notp=%s\nnonce=%s\nstatus=OK",
				time.Now().Format(time.RFC3339),
				r.URL.Query().Get("otp"),
				"not-the-same-nonce",
			)

			readCloser := io.NopCloser(bytes.NewBuffer([]byte(response)))

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       readCloser,
			}
		})

		_, err := client.CheckOTP(otpToken)
		assert.NotNil(t, err)
	})

	t.Run("Non OK status in response body", func(t *testing.T) {
		client := getClient(func(r *http.Request) *http.Response {
			response := fmt.Sprintf(
				"t=%s\notp=%s\nnonce=%s\nstatus=NOT_OK",
				time.Now().Format(time.RFC3339),
				r.URL.Query().Get("otp"),
				r.URL.Query().Get("nonce"),
			)

			readCloser := io.NopCloser(bytes.NewBuffer([]byte(response)))

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       readCloser,
			}
		})

		_, err := client.CheckOTP(otpToken)
		assert.ErrorIs(t, err, ErrOTPInvalid)
	})
}

func TestOTPResponseParse(t *testing.T) {
	matrix := []struct {
		desc       string
		content    []byte
		assertFunc func(*testing.T, *OTPResponse, error)
	}{
		{
			desc:    "No content",
			content: nil,
			assertFunc: func(t *testing.T, otpReponse *OTPResponse, err error) {
				assert.Error(t, err)
			},
		},
		{
			desc:    "No '=' character",
			content: []byte("hello;world"),
			assertFunc: func(t *testing.T, otpReponse *OTPResponse, err error) {
				assert.Nil(t, err)
				assert.Equal(t, "", otpReponse.OTP)
				assert.Equal(t, "", otpReponse.Nonce)
				assert.Equal(t, "", otpReponse.H)
				assert.Equal(t, "", otpReponse.T)
				assert.Equal(t, "", otpReponse.Status)
				assert.Equal(t, "hello;world", otpReponse.raw)
			},
		},
		{
			desc:    "Content",
			content: []byte("h=4uvN1cIqh0vk6bnkO8ya48L2F5c=\nt=2020-01-06T02:52:13Z0998\notp=cccccckdvvulgjvtkjdhtlrbjjctggdihuevikehtlil\nnonce=ba336f7fdb9b8fec5d6d70313125d9985f6d295e\nsl=20\nstatus=OK"),
			assertFunc: func(t *testing.T, otpReponse *OTPResponse, err error) {
				assert.Nil(t, err)
				assert.Equal(t, "cccccckdvvulgjvtkjdhtlrbjjctggdihuevikehtlil", otpReponse.OTP)
				assert.Equal(t, "ba336f7fdb9b8fec5d6d70313125d9985f6d295e", otpReponse.Nonce)
				assert.Equal(t, "4uvN1cIqh0vk6bnkO8ya48L2F5c=", otpReponse.H)
				assert.Equal(t, "2020-01-06T02:52:13Z0998", otpReponse.T)
				assert.Equal(t, "OK", otpReponse.Status)
				assert.Equal(t, "h=4uvN1cIqh0vk6bnkO8ya48L2F5c=\nt=2020-01-06T02:52:13Z0998\notp=cccccckdvvulgjvtkjdhtlrbjjctggdihuevikehtlil\nnonce=ba336f7fdb9b8fec5d6d70313125d9985f6d295e\nsl=20\nstatus=OK", otpReponse.raw)
			},
		},
		{
			desc:    "Content with '\\r' character",
			content: []byte("h=4uvN1cIqh0vk6bnkO8ya48L2F5c=\r\nt=2020-01-06T02:52:13Z0998\r\notp=cccccckdvvulgjvtkjdhtlrbjjctggdihuevikehtlil\r\nnonce=ba336f7fdb9b8fec5d6d70313125d9985f6d295e\r\nsl=20\r\nstatus=OK"),
			assertFunc: func(t *testing.T, otpReponse *OTPResponse, err error) {
				assert.Nil(t, err)
				assert.Equal(t, "cccccckdvvulgjvtkjdhtlrbjjctggdihuevikehtlil", otpReponse.OTP)
				assert.Equal(t, "ba336f7fdb9b8fec5d6d70313125d9985f6d295e", otpReponse.Nonce)
				assert.Equal(t, "4uvN1cIqh0vk6bnkO8ya48L2F5c=", otpReponse.H)
				assert.Equal(t, "2020-01-06T02:52:13Z0998", otpReponse.T)
				assert.Equal(t, "OK", otpReponse.Status)
				assert.Equal(t, "h=4uvN1cIqh0vk6bnkO8ya48L2F5c=\r\nt=2020-01-06T02:52:13Z0998\r\notp=cccccckdvvulgjvtkjdhtlrbjjctggdihuevikehtlil\r\nnonce=ba336f7fdb9b8fec5d6d70313125d9985f6d295e\r\nsl=20\r\nstatus=OK", otpReponse.raw)
			},
		},
	}

	for _, test := range matrix {
		t.Run(test.desc, func(t *testing.T) {
			var token OTPResponse
			err := token.Parse(test.content)
			test.assertFunc(t, &token, err)
		})
	}
}

func TestOTPResponseGetIdentity(t *testing.T) {
	token := OTPResponse{OTP: ""}
	assert.Equal(t, "", token.GetIdentity())

	token = OTPResponse{OTP: "cccccckdvvulgjvtkjdhtlrbjjctggdihuevikehtlil"}
	assert.Equal(t, "cccccckdvvul", token.GetIdentity())
}

func TestValidateOTP(t *testing.T) {
	t.Skip()

	client := Client{
		HTTPClient: http.DefaultClient,
		ClientID:   "1",
	}

	otp := "cccccbenegrnfvfgghcditkerlgvdeifghcrikdebgkt"

	res, err := client.CheckOTP("cccccbenegrnfvfgghcditkerlgvdeifghcrikdebgkt")
	require.Nil(t, err)

	assert.Equal(t, otp, res.OTP, "OTP")
	assert.Equal(t, 40, len(res.Nonce), "Nonce")
	assert.Equal(t, true, len(res.H) > 0, "H")
	assert.Equal(t, true, len(res.T) > 0, "T")
	assert.Equal(t, "REPLAYED_OTP", res.Status, "Status")
}
