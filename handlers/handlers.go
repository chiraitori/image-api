package handlers

import (
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"image-api/pixiv"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randomInt(max int) int {
	return rand.Intn(max)
}

var client *pixiv.Client

func init() {
	cookie := os.Getenv("PIXIV_COOKIE")
	client = pixiv.NewClient(cookie)
}

// Response helpers
type APIError struct {
	Error   bool   `json:"error"`
	Message string `json:"message"`
}

type APISuccess struct {
	Error bool        `json:"error"`
	Data  interface{} `json:"data"`
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, APIError{Error: true, Message: message})
}

func writeSuccess(w http.ResponseWriter, data interface{}) {
	writeJSON(w, http.StatusOK, APISuccess{Error: false, Data: data})
}

// LoginRequest represents login credentials
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Cookie   string `json:"cookie"`
}

// Login handles /api/login requests
func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// If cookie is provided directly, use it
	if req.Cookie != "" {
		client.SetCookie(req.Cookie)
		writeSuccess(w, map[string]interface{}{
			"message":   "Cookie set successfully",
			"logged_in": true,
		})
		return
	}

	// Try username/password login
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "Username and password or cookie required")
		return
	}

	if err := client.Login(req.Username, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	writeSuccess(w, map[string]interface{}{
		"message":   "Login successful",
		"logged_in": true,
	})
}

// AuthStatus handles /api/auth/status requests
func AuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	writeSuccess(w, map[string]interface{}{
		"logged_in":  client.IsLoggedIn(),
		"has_cookie": client.GetCookie() != "",
	})
}

// HealthCheck handles health check requests
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	writeSuccess(w, map[string]string{"status": "ok"})
}

// GetIllust handles /api/illust/{id} requests
func GetIllust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract illust ID from path: /api/illust/12345
	path := strings.TrimPrefix(r.URL.Path, "/api/illust/")
	illustID := strings.TrimSuffix(path, "/")
	
	if illustID == "" {
		writeError(w, http.StatusBadRequest, "Illustration ID is required")
		return
	}

	// Check if pages are requested
	if strings.HasSuffix(path, "/pages") || r.URL.Query().Get("pages") == "true" {
		illustID = strings.TrimSuffix(illustID, "/pages")
		pages, err := client.GetIllustPages(illustID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeSuccess(w, pages)
		return
	}

	illust, err := client.GetIllustDetail(illustID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeSuccess(w, illust)
}

// ProxyImage handles /api/image/ requests to proxy Pixiv images
func ProxyImage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get the image URL from query parameter
	imageURL := r.URL.Query().Get("url")
	if imageURL == "" {
		// Try to extract from path: /api/image/i.pximg.net/...
		path := strings.TrimPrefix(r.URL.Path, "/api/image/")
		if path != "" && path != "/" {
			imageURL = "https://" + path
		}
	}

	if imageURL == "" {
		writeError(w, http.StatusBadRequest, "Image URL is required")
		return
	}

	// Validate that the URL is from Pixiv
	if !strings.Contains(imageURL, "pximg.net") && !strings.Contains(imageURL, "pixiv.net") {
		writeError(w, http.StatusBadRequest, "Only Pixiv image URLs are allowed")
		return
	}

	body, contentType, err := client.ProxyImage(imageURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer body.Close()

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	
	io.Copy(w, body)
}

// SearchIllusts handles /api/search requests
func SearchIllusts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	keyword := r.URL.Query().Get("keyword")
	if keyword == "" {
		keyword = r.URL.Query().Get("q")
	}
	if keyword == "" {
		writeError(w, http.StatusBadRequest, "Search keyword is required")
		return
	}

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	results, err := client.SearchIllusts(keyword, page)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeSuccess(w, results)
}

// RandomImage handles /image requests - shows a random SINGLE image from ranking (no manga)
func RandomImage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "daily"
	}

	// Quality parameter: original (default), regular, small, thumb, mini
	quality := r.URL.Query().Get("quality")
	if quality == "" {
		quality = "original"
	}

	// Fetch ranking to get random image
	results, err := client.GetRanking(mode, 1, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if len(results.Contents) == 0 {
		writeError(w, http.StatusNotFound, "No images found")
		return
	}

	// Filter to only single-page illustrations (not manga)
	// illust_type: "0" = illustration, "1" = manga, "2" = ugoira (animation)
	var singleImages []pixiv.RankingItem
	for _, item := range results.Contents {
		// Only include single-page illustrations (type "0" or empty) with 1 page
		isIllustration := item.IllustType == "0" || item.IllustType == ""
		isSinglePage := item.GetPageCount() <= 1
		if isIllustration && isSinglePage {
			singleImages = append(singleImages, item)
		}
	}

	if len(singleImages) == 0 {
		writeError(w, http.StatusNotFound, "No single illustrations found, try /manga for manga works")
		return
	}

	// Pick a random single image from the results
	idx := randomInt(len(singleImages))
	item := singleImages[idx]

	// Fetch the actual illustration pages to get original quality URL
	illustID := strconv.Itoa(item.GetIllustID())
	pages, err := client.GetIllustPages(illustID)
	
	var imageURL string
	if err == nil && len(pages) > 0 {
		// Use the pages API for best quality
		switch quality {
		case "original":
			imageURL = pages[0].Original
		case "regular":
			imageURL = pages[0].Regular
		case "small":
			imageURL = pages[0].Small
		case "thumb":
			imageURL = pages[0].Thumb
		case "mini":
			imageURL = pages[0].Mini
		default:
			imageURL = pages[0].Original
		}
	}

	// Fallback: try to construct original URL from thumbnail
	if imageURL == "" {
		imageURL = item.URL
		// Remove size constraints and convert to original
		imageURL = strings.Replace(imageURL, "c/240x480/", "", 1)
		imageURL = strings.Replace(imageURL, "c/240x480_80_a2/", "", 1)
		imageURL = strings.Replace(imageURL, "c/128x128/", "", 1)
		imageURL = strings.Replace(imageURL, "c/540x540_70/", "", 1)
		imageURL = strings.Replace(imageURL, "custom-thumb/", "", 1)
		imageURL = strings.Replace(imageURL, "_custom1200", "", 1)
		imageURL = strings.Replace(imageURL, "_master1200", "", 1)
		imageURL = strings.Replace(imageURL, "_square1200", "", 1)
		imageURL = strings.Replace(imageURL, "img-master", "img-original", 1)
		
		// Try common extensions for original
		if !strings.Contains(imageURL, ".") {
			imageURL += ".jpg"
		}
	}

	if imageURL == "" {
		writeError(w, http.StatusNotFound, "Image URL not found")
		return
	}

	// Try to fetch the image, with fallbacks for different extensions
	body, contentType, err := client.ProxyImage(imageURL)
	if err != nil && strings.Contains(imageURL, "img-original") {
		// Try different extensions: png, jpg, gif
		extensions := []string{".png", ".jpg", ".jpeg", ".gif"}
		baseURL := imageURL
		for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif"} {
			baseURL = strings.TrimSuffix(baseURL, ext)
		}
		
		for _, ext := range extensions {
			tryURL := baseURL + ext
			body, contentType, err = client.ProxyImage(tryURL)
			if err == nil {
				break
			}
		}
	}
	
	// Final fallback to thumbnail
	if err != nil {
		body, contentType, err = client.ProxyImage(item.URL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	defer body.Close()

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Illust-ID", strconv.Itoa(item.GetIllustID()))
	w.Header().Set("X-Illust-Title", item.Title)
	w.Header().Set("X-Illust-Author", item.UserName)
	w.Header().Set("X-Image-Quality", quality)

	io.Copy(w, body)
}

// RandomManga handles /manga requests - shows random multi-page manga works
func RandomManga(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "daily"
	}

	// Quality parameter: original (default), regular, small, thumb, mini
	quality := r.URL.Query().Get("quality")
	if quality == "" {
		quality = "original"
	}

	// Page parameter: which page of the manga to show (0-indexed, default random)
	pageParam := r.URL.Query().Get("page")
	requestedPage := -1 // -1 means random
	if pageParam != "" {
		if parsed, err := strconv.Atoi(pageParam); err == nil && parsed >= 0 {
			requestedPage = parsed
		}
	}

	// Fetch ranking to get manga
	results, err := client.GetRanking(mode, 1, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if len(results.Contents) == 0 {
		writeError(w, http.StatusNotFound, "No content found")
		return
	}

	// Filter to manga works (type "1" or multi-page works)
	// illust_type: "0" = illustration, "1" = manga, "2" = ugoira (animation)
	var mangaWorks []pixiv.RankingItem
	for _, item := range results.Contents {
		isMangaType := item.IllustType == "1"
		isMultiPage := item.GetPageCount() > 1
		if isMangaType || isMultiPage {
			mangaWorks = append(mangaWorks, item)
		}
	}

	if len(mangaWorks) == 0 {
		writeError(w, http.StatusNotFound, "No manga found, try /image for single illustrations")
		return
	}

	// Pick a random manga from the results
	idx := randomInt(len(mangaWorks))
	item := mangaWorks[idx]

	// Fetch all pages of this manga
	illustID := strconv.Itoa(item.GetIllustID())
	pages, err := client.GetIllustPages(illustID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if len(pages) == 0 {
		writeError(w, http.StatusNotFound, "No pages found for this manga")
		return
	}

	// If "all" is requested, return JSON with all page URLs
	if r.URL.Query().Get("all") == "true" {
		writeSuccess(w, map[string]interface{}{
			"illust_id":   item.GetIllustID(),
			"title":       item.Title,
			"author":      item.UserName,
			"page_count":  len(pages),
			"pages":       pages,
		})
		return
	}

	// Select which page to show
	pageIndex := requestedPage
	if pageIndex < 0 || pageIndex >= len(pages) {
		// Random page
		pageIndex = randomInt(len(pages))
	}

	// Get the image URL for the selected page
	var imageURL string
	switch quality {
	case "original":
		imageURL = pages[pageIndex].Original
	case "regular":
		imageURL = pages[pageIndex].Regular
	case "small":
		imageURL = pages[pageIndex].Small
	case "thumb":
		imageURL = pages[pageIndex].Thumb
	case "mini":
		imageURL = pages[pageIndex].Mini
	default:
		imageURL = pages[pageIndex].Original
	}

	if imageURL == "" {
		writeError(w, http.StatusNotFound, "Image URL not found")
		return
	}

	// Try to fetch the image, with fallbacks for different extensions
	body, contentType, err := client.ProxyImage(imageURL)
	if err != nil && strings.Contains(imageURL, "img-original") {
		// Try different extensions: png, jpg, gif
		extensions := []string{".png", ".jpg", ".jpeg", ".gif"}
		baseURL := imageURL
		for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif"} {
			baseURL = strings.TrimSuffix(baseURL, ext)
		}
		
		for _, ext := range extensions {
			tryURL := baseURL + ext
			body, contentType, err = client.ProxyImage(tryURL)
			if err == nil {
				break
			}
		}
	}
	
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer body.Close()

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Illust-ID", strconv.Itoa(item.GetIllustID()))
	w.Header().Set("X-Illust-Title", item.Title)
	w.Header().Set("X-Illust-Author", item.UserName)
	w.Header().Set("X-Page-Count", strconv.Itoa(len(pages)))
	w.Header().Set("X-Current-Page", strconv.Itoa(pageIndex))
	w.Header().Set("X-Image-Quality", quality)

	io.Copy(w, body)
}

// GetRanking handles /api/ranking requests
func GetRanking(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "daily"
	}

	// Validate mode
	validModes := map[string]bool{
		"daily":          true,
		"weekly":         true,
		"monthly":        true,
		"rookie":         true,
		"original":       true,
		"daily_r18":      true,
		"weekly_r18":     true,
		"male":           true,
		"female":         true,
		"daily_ai":       true,
	}
	if !validModes[mode] {
		writeError(w, http.StatusBadRequest, "Invalid ranking mode")
		return
	}

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	date := r.URL.Query().Get("date")

	results, err := client.GetRanking(mode, page, date)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeSuccess(w, results)
}
