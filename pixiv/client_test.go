package pixiv

import (
	"net/http"
	"testing"
)

func TestNormalizeCookie(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "raw PHPSESSID", in: "abc123", want: "PHPSESSID=abc123"},
		{name: "full cookie header", in: "PHPSESSID=abc123; other=value", want: "PHPSESSID=abc123; other=value"},
		{name: "named cookie", in: "PHPSESSID=abc123", want: "PHPSESSID=abc123"},
		{name: "colon cookie", in: "PHPSESSID: abc123", want: "PHPSESSID=abc123"},
		{name: "trimmed", in: " abc123 ", want: "PHPSESSID=abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeCookie(tt.in); got != tt.want {
				t.Fatalf("normalizeCookie(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestShouldRetryWithoutAuth(t *testing.T) {
	tests := []struct {
		name string
		resp *http.Response
		want bool
	}{
		{name: "unauthorized", resp: &http.Response{StatusCode: http.StatusUnauthorized}, want: true},
		{name: "forbidden", resp: &http.Response{StatusCode: http.StatusForbidden}, want: true},
		{name: "html login page", resp: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		}, want: true},
		{name: "json ok", resp: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRetryWithoutAuth(tt.resp); got != tt.want {
				t.Fatalf("shouldRetryWithoutAuth() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestImageURLNormalizeAndQuality(t *testing.T) {
	urls := ImageURL{
		ThumbMini: "thumb-mini.jpg",
		Small:     "small.jpg",
		Regular:   "regular.jpg",
		Original:  "original.jpg",
	}

	urls.Normalize()

	if urls.Mini != "thumb-mini.jpg" {
		t.Fatalf("Mini = %q, want thumb-mini.jpg", urls.Mini)
	}
	if urls.Thumb != "thumb-mini.jpg" {
		t.Fatalf("Thumb = %q, want thumb-mini.jpg", urls.Thumb)
	}
	if got := urls.URLForQuality("mini"); got != "thumb-mini.jpg" {
		t.Fatalf("URLForQuality(mini) = %q, want thumb-mini.jpg", got)
	}
	if got := urls.URLForQuality("thumb"); got != "thumb-mini.jpg" {
		t.Fatalf("URLForQuality(thumb) = %q, want thumb-mini.jpg", got)
	}
	if got := urls.URLForQuality("regular"); got != "regular.jpg" {
		t.Fatalf("URLForQuality(regular) = %q, want regular.jpg", got)
	}
}
