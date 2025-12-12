package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var kemonoClient = &http.Client{
	Timeout: 30 * time.Second,
}

const KEMONO_BASE_URL = "https://kemono.cr"
const KEMONO_API_URL = "https://kemono.cr/api/v1"

// KemonoPosts godoc
// @Summary Get Kemono posts by service
// @Description Returns posts from a specific Kemono service (fanbox, patreon, etc.)
// @Tags Kemono
// @Produce json
// @Param service path string true "Service name (fanbox, patreon, discord, fantia, afdian, boosty, gumroad, subscribestar, dlsite)"
// @Param o query int false "Offset for pagination"
// @Success 200 {array} object
// @Failure 500 {object} map[string]string
// @Router /api/kemono/{service}/posts [get]
func KemonoPosts(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/kemono/")
	parts := strings.Split(path, "/")

	var apiURL string

	// Route: /{service}/posts - NOT actually per-service, just use /v1/posts
	if len(parts) == 2 && parts[1] == "posts" {
		offset := r.URL.Query().Get("o")
		apiURL = fmt.Sprintf("%s/posts", KEMONO_API_URL)
		if offset != "" {
			apiURL += "?o=" + offset
		}
	// Route: /{service}/user/{user_id}
	} else if len(parts) == 3 && parts[1] == "user" {
		service := parts[0]
		userId := parts[2]
		offset := r.URL.Query().Get("o")
		apiURL = fmt.Sprintf("%s/%s/user/%s", KEMONO_API_URL, service, userId)
		if offset != "" {
			apiURL += "?o=" + offset
		}
	// Route: /{service}/user/{user_id}/post/{post_id}
	} else if len(parts) == 5 && parts[1] == "user" && parts[3] == "post" {
		service := parts[0]
		userId := parts[2]
		postId := parts[4]
		apiURL = fmt.Sprintf("%s/%s/user/%s/post/%s", KEMONO_API_URL, service, userId, postId)
	} else {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	data, err := fetchKemonoAPI(apiURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(data)
}

// KemonoCreators godoc
// @Summary Get all Kemono creators
// @Description Returns list of all creators
// @Tags Kemono
// @Produce json
// @Success 200 {array} object
// @Failure 500 {object} map[string]string
// @Router /api/kemono/creators [get]
func KemonoCreators(w http.ResponseWriter, r *http.Request) {
	apiURL := fmt.Sprintf("%s/creators.txt", KEMONO_API_URL)

	data, err := fetchKemonoAPI(apiURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(data)
}

// KemonoProxy godoc
// @Summary Proxy Kemono files (images/videos)
// @Description Proxies files from Kemono CDN
// @Tags Kemono
// @Produce octet-stream
// @Param path query string true "File path on Kemono"
// @Success 200 {file} binary
// @Failure 500 {object} map[string]string
// @Router /api/kemono/proxy [get]
func KemonoProxy(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		http.Error(w, "Missing path parameter", http.StatusBadRequest)
		return
	}

	var fileURL string
	if strings.HasPrefix(path, "http") {
		fileURL = path
	} else {
		fileURL = KEMONO_BASE_URL + path
	}

	req, err := http.NewRequest("GET", fileURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Referer", KEMONO_BASE_URL)

	resp, err := kemonoClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Copy headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func fetchKemonoAPI(apiURL string) ([]byte, error) {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", KEMONO_BASE_URL)

	resp, err := kemonoClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kemono API returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Validate JSON
	var js json.RawMessage
	if err := json.Unmarshal(data, &js); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %v", err)
	}

	return data, nil
}
