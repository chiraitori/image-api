package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Paperback Source Repository structures
type PaperbackSourceInfo struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Version       string   `json:"version"`
	Icon          string   `json:"icon"`
	Language      string   `json:"language"`
	ContentRating string   `json:"contentRating"`
	Badges        []string `json:"badges,omitempty"`
}

type PaperbackRepository struct {
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Sources     []PaperbackSourceInfo `json:"sources"`
}

type PaperbackManga struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Author      string   `json:"author"`
	Artist      string   `json:"artist"`
	Desc        string   `json:"desc"`
	Cover       string   `json:"image"`
	Status      string   `json:"status"`
	Tags        []PBTag  `json:"tags,omitempty"`
	LastUpdate  string   `json:"lastUpdate,omitempty"`
	Hentai      bool     `json:"hentai"`
}

type PBTag struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type PaperbackChapter struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	ChapNum   float64 `json:"chapNum"`
	Time      float64 `json:"time"`
	MangaID   string  `json:"mangaId"`
	LangCode  string  `json:"langCode"`
}

type PaperbackHomeSection struct {
	ID    string           `json:"id"`
	Title string           `json:"title"`
	Items []PaperbackManga `json:"items"`
	Type  string           `json:"type"`
}

// PaperbackVersioning handles GET /paperback/versioning.json
func PaperbackVersioning(w http.ResponseWriter, r *http.Request) {
	versioning := map[string]interface{}{
		"buildTime": "2024-12-01T00:00:00Z",
		"sources": []map[string]interface{}{
			{
				"id":            "pixiv",
				"name":          "Pixiv",
				"version":       "1.0.0",
				"icon":          "icon.png",
				"description":   "Browse and read manga from Pixiv",
				"contentRating": "ADULT",
				"language":      "ja",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(versioning)
}

// PaperbackSourceList handles GET /paperback/ - repository listing
func PaperbackSourceList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":        "Pixiv Source",
		"description": "Read manga and illustrations from Pixiv",
		"author":      "image-api",
		"sources": []map[string]interface{}{
			{
				"id":            "pixiv",
				"name":          "Pixiv",
				"version":       "1.0.0",
				"icon":          "icon.png",
				"description":   "Browse and read manga from Pixiv",
				"contentRating": "ADULT",
				"language":      "ja",
				"websiteBaseURL": "https://www.pixiv.net",
			},
		},
	})
}

// PaperbackHome handles GET /paperback/pixiv - home sections
func PaperbackHome(w http.ResponseWriter, r *http.Request) {
	sections := []PaperbackHomeSection{}

	// Daily ranking
	dailyResults, err := client.GetRanking("daily", 1, "")
	if err == nil {
		var items []PaperbackManga
		for _, item := range dailyResults.Contents {
			if item.GetPageCount() > 1 || item.IllustType == "1" {
				items = append(items, PaperbackManga{
					ID:     strconv.Itoa(item.GetIllustID()),
					Title:  item.Title,
					Author: item.UserName,
					Artist: item.UserName,
					Cover:  buildImageProxyURL(r, item.URL),
					Status: "Completed",
					Hentai: false,
				})
				if len(items) >= 15 {
					break
				}
			}
		}
		if len(items) > 0 {
			sections = append(sections, PaperbackHomeSection{
				ID:    "daily",
				Title: "Daily Ranking",
				Items: items,
				Type:  "singleRowNormal",
			})
		}
	}

	// Weekly ranking
	weeklyResults, err := client.GetRanking("weekly", 1, "")
	if err == nil {
		var items []PaperbackManga
		for _, item := range weeklyResults.Contents {
			if item.GetPageCount() > 1 || item.IllustType == "1" {
				items = append(items, PaperbackManga{
					ID:     strconv.Itoa(item.GetIllustID()),
					Title:  item.Title,
					Author: item.UserName,
					Artist: item.UserName,
					Cover:  buildImageProxyURL(r, item.URL),
					Status: "Completed",
					Hentai: false,
				})
				if len(items) >= 15 {
					break
				}
			}
		}
		if len(items) > 0 {
			sections = append(sections, PaperbackHomeSection{
				ID:    "weekly",
				Title: "Weekly Ranking",
				Items: items,
				Type:  "singleRowNormal",
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(sections)
}

// PaperbackSearch handles GET /paperback/pixiv/search
func PaperbackSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	if query == "" {
		query = r.URL.Query().Get("q")
	}
	if query == "" {
		query = r.URL.Query().Get("title")
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if query == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"results": []PaperbackManga{}})
		return
	}

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	results, err := client.SearchIllusts(query, page)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"results": []PaperbackManga{}})
		return
	}

	var mangaList []PaperbackManga
	for _, item := range results.Illusts {
		mangaList = append(mangaList, PaperbackManga{
			ID:     item.ID,
			Title:  item.Title,
			Author: item.UserName,
			Artist: item.UserName,
			Cover:  buildImageProxyURL(r, item.Thumbnail),
			Status: "Completed",
			Hentai: false,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"results": mangaList})
}

// PaperbackMangaDetails handles GET /paperback/pixiv/manga/{id}
func PaperbackMangaDetails(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/paperback/pixiv/manga/")
	mangaID := strings.Split(path, "/")[0]

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if mangaID == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Manga ID required"})
		return
	}

	illust, err := client.GetIllustDetail(mangaID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	var tags []PBTag
	for _, tag := range illust.Tags.Tags {
		tags = append(tags, PBTag{ID: tag.Tag, Label: tag.Tag})
	}

	coverURL := illust.URLs.Regular
	if coverURL == "" {
		coverURL = illust.URLs.Small
	}

	manga := PaperbackManga{
		ID:         illust.ID,
		Title:      illust.Title,
		Author:     illust.UserName,
		Artist:     illust.UserName,
		Desc:       illust.Description,
		Cover:      buildImageProxyURL(r, coverURL),
		Status:     "Completed",
		Tags:       tags,
		LastUpdate: illust.CreateDate,
		Hentai:     false,
	}

	json.NewEncoder(w).Encode(manga)
}

// PaperbackChapters handles GET /paperback/pixiv/manga/{id}/chapters
func PaperbackChapters(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/paperback/pixiv/manga/")
	mangaID := strings.Split(path, "/")[0]

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if mangaID == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"chapters": []PaperbackChapter{}})
		return
	}

	chapters := []PaperbackChapter{
		{
			ID:       mangaID,
			Name:     "Full Work",
			ChapNum:  1,
			Time:     0,
			MangaID:  mangaID,
			LangCode: "jp",
		},
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"chapters": chapters})
}

// PaperbackPages handles GET /paperback/pixiv/chapter/{id}
func PaperbackPages(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/paperback/pixiv/chapter/")
	chapterID := strings.Split(path, "/")[0]

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if chapterID == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"pages": []string{}})
		return
	}

	pages, err := client.GetIllustPages(chapterID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"pages": []string{}})
		return
	}

	var pageURLs []string
	for _, page := range pages {
		imageURL := page.Original
		if imageURL == "" {
			imageURL = page.Regular
		}
		pageURLs = append(pageURLs, buildImageProxyURL(r, imageURL))
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"pages": pageURLs})
}

// PaperbackRouter handles all /paperback/ routes
func PaperbackRouter(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == "/paperback/" || path == "/paperback":
		PaperbackSourceList(w, r)
	case path == "/paperback/versioning.json":
		PaperbackVersioning(w, r)
	case path == "/paperback/pixiv" || path == "/paperback/pixiv/":
		PaperbackHome(w, r)
	case path == "/paperback/pixiv/search":
		PaperbackSearch(w, r)
	case strings.HasPrefix(path, "/paperback/pixiv/manga/") && strings.HasSuffix(path, "/chapters"):
		PaperbackChapters(w, r)
	case strings.HasPrefix(path, "/paperback/pixiv/manga/"):
		PaperbackMangaDetails(w, r)
	case strings.HasPrefix(path, "/paperback/pixiv/chapter/"):
		PaperbackPages(w, r)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(map[string]string{"error": "Not found"})
	}
}

// Helper to build full URL for images
func buildImageProxyURL(r *http.Request, imageURL string) string {
	if imageURL == "" {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
		scheme = fwd
	}
	host := r.Host
	return scheme + "://" + host + "/api/image/?url=" + imageURL
}
