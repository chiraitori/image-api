package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestParseR18Preference(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		mode         string
		envBlock     string
		wantAllow    bool
		wantBlock    bool
		wantResolved string
	}{
		{
			name:         "default daily",
			url:          "/image",
			mode:         "",
			wantAllow:    false,
			wantBlock:    true,
			wantResolved: "daily",
		},
		{
			name:         "explicit r18 true",
			url:          "/image?r18=true",
			mode:         "",
			wantAllow:    true,
			wantBlock:    false,
			wantResolved: "daily_r18",
		},
		{
			name:         "explicit nsfw 1",
			url:          "/image?nsfw=1",
			mode:         "weekly",
			wantAllow:    true,
			wantBlock:    false,
			wantResolved: "weekly_r18",
		},
		{
			name:         "explicit safe true",
			url:          "/image?safe=true&mode=daily_r18",
			mode:         "daily_r18",
			wantAllow:    false,
			wantBlock:    true,
			wantResolved: "daily",
		},
		{
			name:         "block_r18 query",
			url:          "/image?block_r18=1",
			mode:         "daily",
			wantAllow:    false,
			wantBlock:    true,
			wantResolved: "daily",
		},
		{
			name:         "env block r18",
			url:          "/image?r18=true",
			mode:         "daily_r18",
			envBlock:     "true",
			wantAllow:    false,
			wantBlock:    true,
			wantResolved: "daily",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envBlock != "" {
				os.Setenv("BLOCK_R18", tt.envBlock)
				defer os.Unsetenv("BLOCK_R18")
			} else {
				os.Unsetenv("BLOCK_R18")
			}

			req := httptest.NewRequest("GET", tt.url, nil)
			allow, block, resolved := parseR18Preference(req, tt.mode)
			if allow != tt.wantAllow || block != tt.wantBlock || resolved != tt.wantResolved {
				t.Fatalf("got (allow=%v, block=%v, resolved=%q), want (allow=%v, block=%v, resolved=%q)",
					allow, block, resolved, tt.wantAllow, tt.wantBlock, tt.wantResolved)
			}
		})
	}
}

func TestCheckAdminAuth(t *testing.T) {
	os.Setenv("ADMIN_API_KEY", "secret-test-key-123")
	defer os.Unsetenv("ADMIN_API_KEY")

	// 1. Missing header / key from external IP
	req := httptest.NewRequest("POST", "/api/auth/token", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	if checkAdminAuth(req) {
		t.Fatal("expected unauthenticated external request to fail")
	}

	// 2. Correct X-Admin-Key header
	reqWithHeader := httptest.NewRequest("POST", "/api/auth/token", nil)
	reqWithHeader.Header.Set("X-Admin-Key", "secret-test-key-123")
	if !checkAdminAuth(reqWithHeader) {
		t.Fatal("expected X-Admin-Key to pass")
	}

	// 3. Correct Bearer token
	reqWithBearer := httptest.NewRequest("POST", "/api/auth/token", nil)
	reqWithBearer.Header.Set("Authorization", "Bearer secret-test-key-123")
	if !checkAdminAuth(reqWithBearer) {
		t.Fatal("expected Bearer token to pass")
	}
}

func TestProxyImageSSRFProtection(t *testing.T) {
	badURLs := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://localhost:8000/api/auth/status",
		"http://evil.com/?pximg.net",
		"http://pximg.net.attacker.com/image.jpg",
		"http://127.0.0.1:8000",
	}

	for _, badURL := range badURLs {
		req := httptest.NewRequest("GET", "/api/image/?url="+badURL, nil)
		w := httptest.NewRecorder()
		ProxyImage(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400 for bad URL %q, got %d", badURL, w.Code)
		}
	}
}

func TestKemonoProxySSRFProtection(t *testing.T) {
	badPaths := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://evil.com/malicious",
		"http://localhost:8000/",
		"http://attacker.com/kemono.cr",
	}

	for _, badPath := range badPaths {
		req := httptest.NewRequest("GET", "/api/kemono/proxy?path="+badPath, nil)
		w := httptest.NewRecorder()
		KemonoProxy(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected status 403 Forbidden for bad path %q, got %d", badPath, w.Code)
		}
	}
}
