package pixiv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	baseURL    = "https://www.pixiv.net"
	ajaxURL    = "https://www.pixiv.net/ajax"
	imageProxy = "https://i.pximg.net"
	loginURL   = "https://accounts.pixiv.net/api/login"

	// OAuth endpoints
	oauthTokenURL = "https://oauth.secure.pixiv.net/auth/token"
	appAPIURL     = "https://app-api.pixiv.net"
)

// OAuth credentials - loaded from environment variables
var (
	oauthClientID     = getEnvOrDefault("PIXIV_CLIENT_ID", "MOBrBDS8blbauoSck0ZfDbtuzpyT")
	oauthClientSecret = getEnvOrDefault("PIXIV_CLIENT_SECRET", "lsACyCD94FhDUtGTXi3QzcFE2uU1hqtDaKeqrdwj")
)

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Client represents a Pixiv API client
type Client struct {
	httpClient   *http.Client
	cookie       string
	accessToken  string
	refreshToken string
	loggedIn     bool
	mu           sync.RWMutex
}

// OAuthTokenResponse represents the OAuth token response from Pixiv
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	User         struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Account   string `json:"account"`
		IsMailAuth bool  `json:"is_mail_authorized"`
	} `json:"user"`
}

// LoginCredentials holds login information
type LoginCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// NewClient creates a new Pixiv client
func NewClient(cookie string) *Client {
	jar, _ := cookiejar.New(nil)
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
		},
		cookie:   cookie,
		loggedIn: cookie != "",
	}
}

// SetCookie updates the client cookie
func (c *Client) SetCookie(cookie string) {
	c.cookie = cookie
	c.loggedIn = cookie != ""
}

// GetCookie returns the current cookie
func (c *Client) GetCookie() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cookie
}

// IsLoggedIn returns whether the client is authenticated
func (c *Client) IsLoggedIn() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loggedIn
}

// SetTokens sets OAuth access and refresh tokens
func (c *Client) SetTokens(accessToken, refreshToken string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accessToken = accessToken
	c.refreshToken = refreshToken
	c.loggedIn = accessToken != ""
}

// GetTokens returns the current OAuth tokens
func (c *Client) GetTokens() (accessToken, refreshToken string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accessToken, c.refreshToken
}

// HasTokens returns whether OAuth tokens are set
func (c *Client) HasTokens() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accessToken != ""
}

// ExchangeCode exchanges an authorization code for access and refresh tokens
func (c *Client) ExchangeCode(code, codeVerifier string) (*OAuthTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", oauthClientID)
	data.Set("client_secret", oauthClientSecret)
	data.Set("code", code)
	data.Set("code_verifier", codeVerifier)
	data.Set("grant_type", "authorization_code")
	data.Set("include_policy", "true")
	data.Set("redirect_uri", "https://app-api.pixiv.net/web/v1/users/auth/pixiv/callback")

	return c.requestToken(data)
}

// RefreshAccessToken refreshes the access token using the refresh token
func (c *Client) RefreshAccessToken() (*OAuthTokenResponse, error) {
	c.mu.RLock()
	refreshToken := c.refreshToken
	c.mu.RUnlock()

	if refreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	data := url.Values{}
	data.Set("client_id", oauthClientID)
	data.Set("client_secret", oauthClientSecret)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("include_policy", "true")

	return c.requestToken(data)
}

// requestToken makes a token request to Pixiv OAuth endpoint
func (c *Client) requestToken(data url.Values) (*OAuthTokenResponse, error) {
	req, err := http.NewRequest("POST", oauthTokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "PixivAndroidApp/5.0.234 (Android 11; Pixel 5)")
	req.Header.Set("App-OS", "android")
	req.Header.Set("App-OS-Version", "11")
	req.Header.Set("App-Version", "5.0.234")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OAuth error (status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp OAuthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Store the tokens
	c.SetTokens(tokenResp.AccessToken, tokenResp.RefreshToken)

	return &tokenResp, nil
}

// Login authenticates with Pixiv using username and password
// Note: Pixiv uses a complex login flow with CSRF tokens
// This method sets the cookie directly if provided, or attempts web login
func (c *Client) Login(username, password string) error {
	// First, get the login page to obtain CSRF token
	req, err := http.NewRequest("GET", "https://accounts.pixiv.net/login", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get login page: %w", err)
	}
	defer resp.Body.Close()

	// Extract post_key (CSRF token) from cookies or page
	var postKey string
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "PHPSESSID" || cookie.Name == "p_ab_id" {
			// Store cookies
			c.httpClient.Jar.SetCookies(req.URL, []*http.Cookie{cookie})
		}
	}

	// Read response body to find post_key
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Find post_key in the page
	bodyStr := string(body)
	if idx := strings.Index(bodyStr, `"postKey":"`); idx != -1 {
		start := idx + 11
		end := strings.Index(bodyStr[start:], `"`)
		if end != -1 {
			postKey = bodyStr[start : start+end]
		}
	}

	if postKey == "" {
		// Try alternative method
		if idx := strings.Index(bodyStr, `name="post_key" value="`); idx != -1 {
			start := idx + 23
			end := strings.Index(bodyStr[start:], `"`)
			if end != -1 {
				postKey = bodyStr[start : start+end]
			}
		}
	}

	if postKey == "" {
		return fmt.Errorf("could not find CSRF token, please use cookie-based authentication")
	}

	// Perform login
	formData := url.Values{}
	formData.Set("pixiv_id", username)
	formData.Set("password", password)
	formData.Set("post_key", postKey)
	formData.Set("source", "pc")
	formData.Set("return_to", "https://www.pixiv.net/")

	loginReq, err := http.NewRequest("POST", loginURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}

	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	loginReq.Header.Set("Referer", "https://accounts.pixiv.net/login")

	loginResp, err := c.httpClient.Do(loginReq)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer loginResp.Body.Close()

	// Extract session cookie
	var cookies []string
	for _, cookie := range c.httpClient.Jar.Cookies(loginReq.URL) {
		cookies = append(cookies, cookie.String())
	}

	if len(cookies) > 0 {
		c.cookie = strings.Join(cookies, "; ")
		c.loggedIn = true
		return nil
	}

	return fmt.Errorf("login failed, no session cookie received")
}

// IllustDetail represents the illustration details
type IllustDetail struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	UserID      string      `json:"userId"`
	UserName    string      `json:"userName"`
	Width       int         `json:"width"`
	Height      int         `json:"height"`
	PageCount   int         `json:"pageCount"`
	Tags        TagsWrapper `json:"tags"`
	CreateDate  string      `json:"createDate"`
	URLs        ImageURL    `json:"urls"`
}

// TagsWrapper wraps the tags object from Pixiv API
type TagsWrapper struct {
	AuthorID string `json:"authorId"`
	IsLocked bool   `json:"isLocked"`
	Tags     []Tag  `json:"tags"`
}

// Tag represents an illustration tag
type Tag struct {
	Tag         string            `json:"tag"`
	Translation map[string]string `json:"translation,omitempty"`
	Locked      bool              `json:"locked"`
	Romaji      string            `json:"romaji,omitempty"`
}

// ImageURL contains various image URLs
type ImageURL struct {
	Mini     string `json:"mini"`
	Thumb    string `json:"thumb"`
	Small    string `json:"small"`
	Regular  string `json:"regular"`
	Original string `json:"original"`
}

// APIResponse represents the standard Pixiv API response
type APIResponse struct {
	Error   bool            `json:"error"`
	Message string          `json:"message"`
	Body    json.RawMessage `json:"body"`
}

// SearchResult represents search results
type SearchResult struct {
	Illusts []IllustBrief `json:"illusts"`
	Total   int           `json:"total"`
}

// IllustBrief represents brief illustration info
type IllustBrief struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	UserID    string `json:"userId"`
	UserName  string `json:"userName"`
	Thumbnail string `json:"url"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	PageCount int    `json:"pageCount"`
}

// RankingResult represents ranking results
type RankingResult struct {
	Contents []RankingItem `json:"contents"`
	Mode     string        `json:"mode"`
	Date     string        `json:"date"`
}

// RankingItem represents a single ranking item
type RankingItem struct {
	IllustID        json.Number `json:"illust_id"`
	Title           string      `json:"title"`
	UserID          json.Number `json:"user_id"`
	UserName        string      `json:"user_name"`
	Rank            json.Number `json:"rank"`
	URL             string      `json:"url"`
	Width           json.Number `json:"width"`
	Height          json.Number `json:"height"`
	IllustType      string      `json:"illust_type"`
	IllustPageCount json.Number `json:"illust_page_count"`
}

// GetIllustID returns the illust ID as int
func (r RankingItem) GetIllustID() int {
	v, _ := r.IllustID.Int64()
	return int(v)
}

// GetPageCount returns the page count as int
func (r RankingItem) GetPageCount() int {
	v, _ := r.IllustPageCount.Int64()
	return int(v)
}

// doRequest performs an HTTP request with Pixiv headers
func (c *Client) doRequest(method, url string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Referer", "https://www.pixiv.net/")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	if c.cookie != "" {
		// Check if cookie already has PHPSESSID= prefix
		if strings.HasPrefix(c.cookie, "PHPSESSID=") {
			req.Header.Set("Cookie", c.cookie)
		} else {
			req.Header.Set("Cookie", "PHPSESSID="+c.cookie)
		}
	}

	return c.httpClient.Do(req)
}

// GetIllustDetail fetches illustration details by ID
func (c *Client) GetIllustDetail(illustID string) (*IllustDetail, error) {
	url := fmt.Sprintf("%s/illust/%s", ajaxURL, illustID)
	
	resp, err := c.doRequest("GET", url)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if apiResp.Error {
		return nil, fmt.Errorf("API error: %s", apiResp.Message)
	}

	var illust IllustDetail
	if err := json.Unmarshal(apiResp.Body, &illust); err != nil {
		return nil, fmt.Errorf("failed to unmarshal illust: %w", err)
	}

	return &illust, nil
}

// GetIllustPages fetches all pages of an illustration
func (c *Client) GetIllustPages(illustID string) ([]ImageURL, error) {
	url := fmt.Sprintf("%s/illust/%s/pages", ajaxURL, illustID)
	
	resp, err := c.doRequest("GET", url)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if apiResp.Error {
		return nil, fmt.Errorf("API error: %s", apiResp.Message)
	}

	var pages []struct {
		URLs ImageURL `json:"urls"`
	}
	if err := json.Unmarshal(apiResp.Body, &pages); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pages: %w", err)
	}

	urls := make([]ImageURL, len(pages))
	for i, p := range pages {
		urls[i] = p.URLs
	}

	return urls, nil
}

// SearchIllusts searches for illustrations
func (c *Client) SearchIllusts(keyword string, page int) (*SearchResult, error) {
	escapedKeyword := url.QueryEscape(keyword)
	reqURL := fmt.Sprintf("%s/search/artworks/%s?word=%s&order=date_d&mode=all&p=%d&s_mode=s_tag&type=all", 
		ajaxURL, escapedKeyword, escapedKeyword, page)
	
	resp, err := c.doRequest("GET", reqURL)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if apiResp.Error {
		return nil, fmt.Errorf("API error: %s", apiResp.Message)
	}

	// Try different response structures
	// Structure 1: {illustManga: {data: [...], total: N}}
	var searchBody1 struct {
		IllustManga struct {
			Data  []IllustBrief `json:"data"`
			Total int           `json:"total"`
		} `json:"illustManga"`
	}
	if err := json.Unmarshal(apiResp.Body, &searchBody1); err == nil && len(searchBody1.IllustManga.Data) > 0 {
		return &SearchResult{
			Illusts: searchBody1.IllustManga.Data,
			Total:   searchBody1.IllustManga.Total,
		}, nil
	}

	// Structure 2: {illust: {data: [...], total: N}}  
	var searchBody2 struct {
		Illust struct {
			Data  []IllustBrief `json:"data"`
			Total int           `json:"total"`
		} `json:"illust"`
	}
	if err := json.Unmarshal(apiResp.Body, &searchBody2); err == nil && len(searchBody2.Illust.Data) > 0 {
		return &SearchResult{
			Illusts: searchBody2.Illust.Data,
			Total:   searchBody2.Illust.Total,
		}, nil
	}

	// Structure 3: Popular section {popular: {recent: [...], permanent: [...]}}
	var searchBody3 struct {
		Popular struct {
			Recent    []IllustBrief `json:"recent"`
			Permanent []IllustBrief `json:"permanent"`
		} `json:"popular"`
		IllustManga struct {
			Data  []IllustBrief `json:"data"`
			Total int           `json:"total"`
		} `json:"illustManga"`
	}
	if err := json.Unmarshal(apiResp.Body, &searchBody3); err == nil {
		var illusts []IllustBrief
		illusts = append(illusts, searchBody3.Popular.Recent...)
		illusts = append(illusts, searchBody3.Popular.Permanent...)
		illusts = append(illusts, searchBody3.IllustManga.Data...)
		if len(illusts) > 0 {
			return &SearchResult{
				Illusts: illusts,
				Total:   len(illusts),
			}, nil
		}
	}

	return &SearchResult{
		Illusts: nil,
		Total:   0,
	}, nil
}

// GetRanking fetches illustration ranking
func (c *Client) GetRanking(mode string, page int, date string) (*RankingResult, error) {
	if mode == "" {
		mode = "daily"
	}

	reqURL := fmt.Sprintf("https://www.pixiv.net/ranking.php?mode=%s&p=%d&format=json", mode, page)
	if date != "" {
		reqURL += "&date=" + date
	}
	
	resp, err := c.doRequest("GET", reqURL)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var result RankingResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// ProxyImage fetches an image from Pixiv's image server
func (c *Client) ProxyImage(imageURL string) (io.ReadCloser, string, error) {
	req, err := http.NewRequest("GET", imageURL, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Referer", "https://www.pixiv.net/")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch image: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, "", fmt.Errorf("image server returned status %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	return resp.Body, contentType, nil
}
