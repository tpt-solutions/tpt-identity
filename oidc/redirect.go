package oidc

import "net/url"

// AppendQuery adds params to a redirect target, keeping any query the target already has. Keys
// and values are escaped, so a state or code value cannot inject extra parameters.
func AppendQuery(target string, params map[string]string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
