package detect

import "testing"

// TestPatterns_ConnectionStrings asserts the connstring_password pattern
// captures the embedded password (group 1) for each supported scheme.
//
// Inputs are built via string concatenation so the source file doesn't
// contain whole connection-string shapes (which get redacted in transit
// when this file passes through a noleak proxy).
func TestPatterns_ConnectionStrings(t *testing.T) {
	d := New(Options{})

	type tc struct {
		name string
		in   string
		want string
	}

	mk := func(scheme, user, pass, hostpath string) string {
		return scheme + "://" + user + ":" + pass + "@" + hostpath
	}

	cases := []tc{
		{"mongodb", mk("mongodb+srv", "admin", "plainpw", "cluster0.mongodb.net/test"), "plainpw"},
		{"postgres_simple", mk("postgresql", "user", "pass123", "db.example.com:5432/mydb"), "pass123"},
		{"postgres_at_in_pass", mk("postgresql", "user", "p"+"@"+"ssw0rd123", "db.example.com:5432/mydb"), "p" + "@" + "ssw0rd123"},
		{"mysql", mk("mysql", "root", "rootpw", "db:3306/x"), "rootpw"},
		{"redis", mk("redis", "default", "redispw", "cache:6379/0"), "redispw"},
	}
	for _, c := range cases {
		matches := d.Scan([]byte(c.in))
		found := false
		for _, m := range matches {
			if m.Kind != "connstring_password" {
				continue
			}
			if c.in[m.Start:m.End] == c.want {
				found = true
				break
			}
		}
		if !found {
			var got []string
			for _, m := range matches {
				if m.Kind == "connstring_password" {
					got = append(got, c.in[m.Start:m.End])
				}
			}
			t.Errorf("[%s] expected connstring_password capture %q in %q; got %v",
				c.name, c.want, c.in, got)
		}
	}
}

// TestPatterns_AWSSecretAccessKey asserts the labeled detection works and
// that an unlabeled 40-char base64 blob does NOT match (would be a massive
// false-positive class).
func TestPatterns_AWSSecretAccessKey(t *testing.T) {
	d := New(Options{})

	body := "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
	labeled := `AWS_SECRET_ACCESS_KEY="` + body + `"`
	matches := d.Scan([]byte(labeled))
	if !hasKindForBody(matches, "aws_secret_access_key", []byte(body), []byte(labeled)) {
		t.Errorf("expected labeled aws_secret_access_key match, got %v", kindList(matches))
	}

	unlabeled := `random data: ` + body + ` in a comment`
	for _, m := range d.Scan([]byte(unlabeled)) {
		if m.Kind == "aws_secret_access_key" {
			t.Errorf("aws_secret_access_key matched unlabeled blob: %+v", m)
		}
	}
}

// TestPatterns_HTTPBasicAuth verifies the new Basic Auth pattern catches
// both the `Authorization: Basic <base64>` form and bare `Basic <base64>`.
func TestPatterns_HTTPBasicAuth(t *testing.T) {
	d := New(Options{})
	body := "YWRtaW46" + "U3VwZXJTZWNyZXRQYXNzMTIz"
	cases := []string{
		"Authorization: Basic " + body,
		"Basic " + body,
		"header is Basic " + body + " trailing",
	}
	for _, c := range cases {
		matches := d.Scan([]byte(c))
		hit := false
		for _, m := range matches {
			if m.Kind == "http_basic_auth" && c[m.Start:m.End] == body {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("expected http_basic_auth match in %q, got %v", c, kindList(matches))
		}
	}
}

// TestPatterns_PagerDutyToken verifies the new PagerDuty `u+` prefix pattern.
func TestPatterns_PagerDutyToken(t *testing.T) {
	d := New(Options{})
	body := "u+" + "1234567890abcdefghijklmnopqrstuvwxyz"
	in := "token: " + body
	matches := d.Scan([]byte(in))
	if !hasKindForBody(matches, "pagerduty_token", []byte(body), []byte(in)) {
		t.Errorf("expected pagerduty_token match, got %v", kindList(matches))
	}
}
