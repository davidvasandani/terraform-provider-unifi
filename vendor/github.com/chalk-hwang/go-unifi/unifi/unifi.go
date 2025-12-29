package unifi //

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxRetries       = 5
	baseRetryDelay   = 2 * time.Second
	maxRetryDelay    = 30 * time.Second
)

const (
	apiPath   = "/api"
	apiV2Path = "/v2/api"

	apiPathNew   = "/proxy/network/api"
	apiV2PathNew = "/proxy/network/v2/api"

	loginPath    = "/api/login"
	loginPathNew = "/api/auth/login"

	statusPath    = "/status"
	statusPathNew = "/proxy/network/status"
)

type NotFoundError struct{}

func (err *NotFoundError) Error() string {
	return "not found"
}

type APIError struct {
	RC      string
	Message string
}

func (err *APIError) Error() string {
	return err.Message
}

type Client struct {
	// single thread client calls for CSRF, etc.
	sync.Mutex

	c       *http.Client
	baseURL *url.URL

	apiPath    string
	apiV2Path  string
	loginPath  string
	statusPath string

	csrf   string
	apiKey string

	version string
}

func (c *Client) CSRFToken() string {
	return c.csrf
}

func (c *Client) SetAPIKey(key string) {
	c.apiKey = key
}

func (c *Client) Version() string {
	return c.version
}

func (c *Client) SetBaseURL(base string) error {
	var err error
	c.baseURL, err = url.Parse(base)
	if err != nil {
		return err
	}

	// error for people who are still passing hard coded old paths
	if path := strings.TrimSuffix(c.baseURL.Path, "/"); path == apiPath {
		return fmt.Errorf("expected a base URL without the `/api`, got: %q", c.baseURL)
	}

	return nil
}

func (c *Client) SetHTTPClient(hc *http.Client) error {
	c.c = hc
	return nil
}

func (c *Client) setAPIUrlStyle(ctx context.Context) error {
	// check if new style API
	// this is modified from the unifi-poller (https://github.com/unifi-poller/unifi) implementation.
	// see https://github.com/unifi-poller/unifi/blob/4dc44f11f61a2e08bf7ec5b20c71d5bced837b5d/unifi.go#L101-L104
	// and https://github.com/unifi-poller/unifi/commit/43a6b225031a28f2b358f52d03a7217c7b524143

	// Retry logic for connection issues
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL.String(), nil)
		if err != nil {
			return err
		}

		// We can't share these cookies with other requests, so make a new client.
		// Checking the return code on the first request so don't follow a redirect.
		// Include a timeout to prevent hanging on API style detection.
		client := &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: c.c.Transport,
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue // retry
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		if resp.StatusCode == http.StatusOK {
			// the new API returns a 200 for a / request
			c.apiPath = apiPathNew
			c.apiV2Path = apiV2PathNew
			c.loginPath = loginPathNew
			c.statusPath = statusPathNew
			return nil
		}

		// The old version returns a "302" (to /manage) for a / request
		c.apiPath = apiPath
		c.apiV2Path = apiV2Path
		c.loginPath = loginPath
		c.statusPath = statusPath
		return nil
	}
	return lastErr
}

func (c *Client) Login(ctx context.Context, user, pass string) error {
	if c.c == nil {
		c.c = &http.Client{}

		jar, _ := cookiejar.New(nil)
		c.c.Jar = jar
	}

	err := c.setAPIUrlStyle(ctx)
	if err != nil {
		return fmt.Errorf("unable to determine API URL style: %w", err)
	}

	var status struct {
		Meta struct {
			ServerVersion string `json:"server_version"`
			UUID          string `json:"uuid"`
		} `json:"meta"`
	}

	err = c.do(ctx, "POST", c.loginPath, &struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		Username: user,
		Password: pass,
	}, nil)
	if err != nil {
		return err
	}

	err = c.do(ctx, "GET", c.statusPath, nil, &status)
	if err != nil {
		return err
	}

	if version := status.Meta.ServerVersion; version != "" {
		c.version = status.Meta.ServerVersion
		return nil
	}

	// newer version of 6.0 controller, use sysinfo to determine version
	// using default site since it must exist
	si, err := c.sysinfo(ctx, "default")
	if err != nil {
		return err
	}

	c.version = si.Version

	if c.version == "" {
		return errors.New("unable to determine controller version")
	}

	return nil
}

// InitWithAPIKey initializes the client with API key authentication instead of username/password
func (c *Client) InitWithAPIKey(ctx context.Context, apiKey string) error {
	if c.c == nil {
		c.c = &http.Client{}
	}

	c.apiKey = apiKey

	err := c.setAPIUrlStyle(ctx)
	if err != nil {
		return fmt.Errorf("unable to determine API URL style: %w", err)
	}

	var status struct {
		Meta struct {
			ServerVersion string `json:"server_version"`
			UUID          string `json:"uuid"`
		} `json:"meta"`
	}

	err = c.do(ctx, "GET", c.statusPath, nil, &status)
	if err != nil {
		return err
	}

	if version := status.Meta.ServerVersion; version != "" {
		c.version = status.Meta.ServerVersion
		return nil
	}

	// newer version of 6.0 controller, use sysinfo to determine version
	// using default site since it must exist
	si, err := c.sysinfo(ctx, "default")
	if err != nil {
		return err
	}

	c.version = si.Version

	if c.version == "" {
		return errors.New("unable to determine controller version")
	}

	return nil
}

func (c *Client) do(ctx context.Context, method, relativeURL string, reqBody interface{}, respBody interface{}) error {
	// single threading requests, this is mostly to assist in CSRF token propagation
	c.Lock()
	defer c.Unlock()

	var reqBytes []byte
	var err error
	if reqBody != nil {
		reqBytes, err = json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("unable to marshal JSON: %s %s %w", method, relativeURL, err)
		}
	}

	reqURL, err := url.Parse(relativeURL)
	if err != nil {
		return fmt.Errorf("unable to parse URL: %s %s %w", method, relativeURL, err)
	}
	if !strings.HasPrefix(relativeURL, "/") && !reqURL.IsAbs() {
		reqURL.Path = path.Join(c.apiPath, reqURL.Path)
	}

	fullURL := c.baseURL.ResolveReference(reqURL)

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		// Create fresh reader for each attempt (request body can only be read once)
		var reqReader io.Reader
		if reqBytes != nil {
			reqReader = bytes.NewReader(reqBytes)
		}

		req, err := http.NewRequestWithContext(ctx, method, fullURL.String(), reqReader)
		if err != nil {
			return fmt.Errorf("unable to create request: %s %s %w", method, relativeURL, err)
		}

		req.Header.Set("User-Agent", "terraform-provider-unifi/0.1")
		req.Header.Add("Content-Type", "application/json; charset=utf-8")

		if c.apiKey != "" {
			req.Header.Set("X-API-KEY", c.apiKey)
		}

		if c.csrf != "" {
			req.Header.Set("X-Csrf-Token", c.csrf)
		}

		resp, err := c.c.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("unable to perform request: %s %s %w", method, relativeURL, err)
			continue
		}

		// Update CSRF token if present
		if csrf := resp.Header.Get("X-Csrf-Token"); csrf != "" {
			c.csrf = csrf
		}

		// Handle rate limiting (429 Too Many Requests)
		if resp.StatusCode == http.StatusTooManyRequests {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			retryDelay := c.calculateRetryDelay(resp, attempt)
			log.Printf("[WARN] Rate limited (429) for %s %s, retrying in %v (attempt %d/%d)",
				method, relativeURL, retryDelay, attempt+1, maxRetries)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryDelay):
				continue
			}
		}

		// Handle not found
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return &NotFoundError{}
		}

		// Handle other errors
		if resp.StatusCode != http.StatusOK {
			errBody := struct {
				Meta meta `json:"meta"`
				Data []struct {
					Meta meta `json:"meta"`
				} `json:"data"`
			}{}
			if err = json.NewDecoder(resp.Body).Decode(&errBody); err != nil {
				resp.Body.Close()
				return err
			}
			resp.Body.Close()

			var apiErr error
			if len(errBody.Data) > 0 && errBody.Data[0].Meta.RC == "error" {
				apiErr = errBody.Data[0].Meta.error()
			}
			if apiErr == nil {
				apiErr = errBody.Meta.error()
			}
			return fmt.Errorf("%w (%s) for %s %s", apiErr, resp.Status, method, fullURL.String())
		}

		// Success - decode response if needed
		if respBody == nil || resp.ContentLength == 0 {
			resp.Body.Close()
			return nil
		}

		err = json.NewDecoder(resp.Body).Decode(respBody)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("unable to decode body: %s %s %w", method, relativeURL, err)
		}

		return nil
	}

	if lastErr != nil {
		return fmt.Errorf("max retries exceeded after %d attempts: %w", maxRetries, lastErr)
	}
	return fmt.Errorf("max retries exceeded after %d attempts due to rate limiting", maxRetries)
}

// calculateRetryDelay determines how long to wait before retrying
func (c *Client) calculateRetryDelay(resp *http.Response, attempt int) time.Duration {
	// Check for Retry-After header
	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
		// Try parsing as seconds
		if seconds, err := strconv.Atoi(retryAfter); err == nil {
			delay := time.Duration(seconds) * time.Second
			if delay > maxRetryDelay {
				return maxRetryDelay
			}
			return delay
		}
		// Try parsing as HTTP date (RFC1123)
		if t, err := time.Parse(time.RFC1123, retryAfter); err == nil {
			delay := time.Until(t)
			if delay > maxRetryDelay {
				return maxRetryDelay
			}
			if delay > 0 {
				return delay
			}
		}
	}

	// Exponential backoff with jitter
	delay := baseRetryDelay * time.Duration(1<<uint(attempt))
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	return delay
}

type meta struct {
	RC      string `json:"rc"`
	Message string `json:"msg"`
}

func (m *meta) error() error {
	if m.RC != "ok" {
		return &APIError{
			RC:      m.RC,
			Message: m.Message,
		}
	}

	return nil
}
