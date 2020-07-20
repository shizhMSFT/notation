package registry

import (
	"net/http"
)

// Client is a customized registry client
type Client struct {
	base     http.RoundTripper
	insecure bool
}

// ClientOptions configures the client
type ClientOptions struct {
	Username string
	Password string
	Insecure bool
}

// NewClient creates a new registry client
func NewClient(base http.RoundTripper, opts *ClientOptions) *Client {
	if base == nil {
		base = http.DefaultTransport
	}
	if opts == nil {
		opts = &ClientOptions{}
	}
	return &Client{
		base:     newV2transport(base, opts.Username, opts.Password),
		insecure: opts.Insecure,
	}
}
