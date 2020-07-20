package registry

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var authHeaderRegex = regexp.MustCompile(`(realm|service|scope)="([^"]*)`)

type v2Transport struct {
	base     http.RoundTripper
	username string
	password string
}

func newV2transport(base http.RoundTripper, username, password string) http.RoundTripper {
	return &v2Transport{
		base:     base,
		username: username,
		password: password,
	}
}

func (t *v2Transport) RoundTrip(originalReq *http.Request) (*http.Response, error) {
	req := originalReq.Clone(originalReq.Context())
	if t.username != "" {
		req.SetBasicAuth(t.username, t.password)
	}

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	scheme, params := parseAuthHeader(resp.Header.Get("Www-Authenticate"))
	if scheme != "bearer" {
		return resp, nil
	}
	resp.Body.Close()

	token, resp, err := t.fetchToken(params)
	if err != nil {
		if resp != nil {
			return resp, nil
		}
		return nil, err
	}

	req = originalReq.Clone(originalReq.Context())
	req.Header.Set("Authorization", "Bearer "+token)
	return t.base.RoundTrip(req)
}

func (t *v2Transport) fetchToken(params map[string]string) (string, *http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, params["realm"], nil)
	if err != nil {
		return "", nil, err
	}
	if t.username != "" {
		req.SetBasicAuth(t.username, t.password)
	}

	query := url.Values{}
	if service, ok := params["service"]; ok {
		query.Set("service", service)
	}
	if scope, ok := params["scope"]; ok {
		query.Set("scope", scope)
	}
	req.URL.RawQuery = query.Encode()

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", resp, nil
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, err
	}
	return result.AccessToken, nil, nil
}

func parseAuthHeader(header string) (string, map[string]string) {
	parts := strings.SplitN(header, " ", 2)
	scheme := strings.ToLower(parts[0])
	if len(parts) < 2 {
		return scheme, nil
	}

	params := make(map[string]string)
	result := authHeaderRegex.FindAllStringSubmatch(parts[1], -1)
	for _, match := range result {
		params[strings.ToLower(match[1])] = match[2]
	}

	return scheme, params
}
