package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"log"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/redis/go-redis/v9"
	"golang.org/x/image/draw"
	"image-api/pixiv"
)

type PoolItemMeta struct {
	IllustID    int     `json:"illust_id"`
	Title       string  `json:"title"`
	Author      string  `json:"author"`
	ContentType string  `json:"content_type"`
	Size        int64   `json:"size"`
	Width       int     `json:"width"`
	Height      int     `json:"height"`
	AspectRatio float64 `json:"aspect_ratio"`
	IsR18       bool    `json:"is_r18"`
	Key         string  `json:"key"`
}

type RandomPool struct {
	s3Client    *minio.Client
	redisClient *redis.Client
	bucket      string
	targetBytes int64
	pixivClient *pixiv.Client
	enabled     bool
	mu          sync.RWMutex
}

var Pool *RandomPool

// InitPool initializes the MinIO and Redis storage connections
func InitPool(pixivCl *pixiv.Client) {
	s3Endpoint := os.Getenv("S3_ENDPOINT")
	if s3Endpoint == "" {
		s3Endpoint = "localhost:9000"
	}

	accessKey := os.Getenv("S3_ACCESS_KEY")
	if accessKey == "" {
		accessKey = "minioadmin"
	}
	secretKey := os.Getenv("S3_SECRET_KEY")
	if secretKey == "" {
		secretKey = "minioadmin"
	}
	bucket := os.Getenv("S3_BUCKET")
	if bucket == "" {
		bucket = "pixiv-images"
	}
	useSSL := strings.ToLower(os.Getenv("S3_USE_SSL")) == "true"

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	redisPassword := os.Getenv("REDIS_PASSWORD")

	targetGB := 5
	if tg := os.Getenv("RANDOM_POOL_TARGET_GB"); tg != "" {
		if parsed, err := strconv.Atoi(tg); err == nil && parsed > 0 {
			targetGB = parsed
		}
	}
	targetBytes := int64(targetGB) * 1024 * 1024 * 1024

	// Initialize S3
	s3, err := minio.New(s3Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		log.Printf("[Pool] S3 client init error: %v (pool disabled)", err)
		return
	}

	// Initialize Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Printf("[Pool] Redis ping failed: %v (pool disabled, falling back to live Pixiv)", err)
		return
	}

	// Ensure S3 bucket exists
	ctxBucket, cancelBucket := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelBucket()
	exists, errBucket := s3.BucketExists(ctxBucket, bucket)
	if errBucket != nil || !exists {
		errMake := s3.MakeBucket(ctxBucket, bucket, minio.MakeBucketOptions{})
		if errMake != nil {
			log.Printf("[Pool] MakeBucket %s failed: %v", bucket, errMake)
		} else {
			log.Printf("[Pool] Created S3 bucket: %s", bucket)
		}
	}

	Pool = &RandomPool{
		s3Client:    s3,
		redisClient: rdb,
		bucket:      bucket,
		targetBytes: targetBytes,
		pixivClient: pixivCl,
		enabled:     true,
	}

	log.Printf("[Pool] Initialized S3 (%s) and Redis (%s) random image pool (target: %d GB)", s3Endpoint, redisAddr, targetGB)

	// Clean out any old low-res or 9:16 images, then run crawler
	go func() {
		Pool.PurgeLowResAndPortrait(context.Background())
		Pool.startCrawler()
	}()
}

var rePixivCrop = regexp.MustCompile(`/c/[^/]+/`)

// GetHighResCandidateURLs transforms any thumbnail URL into full 1080p/2K/original Pixiv URLs
func GetHighResCandidateURLs(imageURL string) []string {
	if imageURL == "" {
		return nil
	}
	// Strip crop path (e.g. /c/480x960/, /c/240x480/, /custom-thumb/)
	masterURL := rePixivCrop.ReplaceAllString(imageURL, "/")
	masterURL = strings.Replace(masterURL, "/custom-thumb/", "/", 1)

	// Build original URL candidate by stripping _master1200 and changing path to /img-original/
	baseOrig := masterURL
	baseOrig = strings.Replace(baseOrig, "_master1200", "", 1)
	baseOrig = strings.Replace(baseOrig, "_custom1200", "", 1)
	baseOrig = strings.Replace(baseOrig, "_square1200", "", 1)
	baseOrig = strings.Replace(baseOrig, "/img-master/", "/img-original/", 1)

	for _, ext := range []string{".jpg", ".png", ".jpeg", ".gif", ".webp"} {
		baseOrig = strings.TrimSuffix(baseOrig, ext)
	}

	// 1. Try full original 2K/4K JPG
	// 2. Try full original 2K/4K PNG
	// 3. Fallback to 1200p Master (crisp ~1080p/2K quality, never 480px thumbnail)
	return []string{
		baseOrig + ".jpg",
		baseOrig + ".png",
		masterURL,
	}
}

// OptimizeImageForCache resizes large images to max dimension (e.g. 2048 for 2K)
// and compresses with JPEG quality ~82 to optimize S3 storage usage.
func OptimizeImageForCache(rawBytes []byte, maxDim int, quality int) ([]byte, int, int, string, error) {
	if maxDim <= 0 {
		maxDim = 2048 // 2K max dimension
	}
	if quality <= 0 {
		quality = 82
	}

	img, _, err := image.Decode(bytes.NewReader(rawBytes))
	if err != nil {
		return rawBytes, 0, 0, "image/jpeg", nil
	}

	bounds := img.Bounds()
	w := bounds.Dx()
	h := bounds.Dy()

	targetW := w
	targetH := h

	// Scale down if exceeds maxDim
	if w > maxDim || h > maxDim {
		if w >= h {
			targetW = maxDim
			targetH = int(float64(h) * float64(maxDim) / float64(w))
		} else {
			targetH = maxDim
			targetW = int(float64(w) * float64(maxDim) / float64(h))
		}
	}

	var dst image.Image
	if targetW != w || targetH != h {
		dstImg := image.NewRGBA(image.Rect(0, 0, targetW, targetH))
		draw.BiLinear.Scale(dstImg, dstImg.Bounds(), img, bounds, draw.Over, nil)
		dst = dstImg
	} else {
		dst = img
	}

	var buf bytes.Buffer
	err = jpeg.Encode(&buf, dst, &jpeg.Options{Quality: quality})
	if err != nil {
		return rawBytes, w, h, "image/jpeg", nil
	}

	return buf.Bytes(), targetW, targetH, "image/jpeg", nil
}

// IsEnabled returns true if pool is operational
func (p *RandomPool) IsEnabled() bool {
	return p != nil && p.enabled
}

// PurgeLowResAndPortrait cleans out any non-16:9/4:3 images (<1.25), 9:16 portraits, or <150KB thumbnails
func (p *RandomPool) PurgeLowResAndPortrait(ctx context.Context) (int, error) {
	if !p.IsEnabled() {
		return 0, nil
	}
	keys, err := p.redisClient.SMembers(ctx, "random_pool:keys:all").Result()
	if err != nil {
		return 0, err
	}

	purged := 0
	for _, key := range keys {
		metaData, err := p.redisClient.Get(ctx, "random_pool:meta:"+key).Result()
		shouldDelete := false
		if err != nil || metaData == "" {
			shouldDelete = true
		} else {
			var meta PoolItemMeta
			if err := json.Unmarshal([]byte(metaData), &meta); err != nil {
				shouldDelete = true
			} else {
				// Purge if vertical portrait / 9:16 (< 0.95 or > 2.6) or low-res (< 150KB)
				if meta.AspectRatio < 0.95 || meta.AspectRatio > 2.6 || meta.Size < 150*1024 {
					shouldDelete = true
				}
				// If item is R18, strictly remove it from the safe set
				if meta.IsR18 {
					p.redisClient.SRem(ctx, "random_pool:keys:safe", key)
				}
			}
		}

		if shouldDelete {
			p.s3Client.RemoveObject(ctx, p.bucket, key, minio.RemoveObjectOptions{})
			p.redisClient.SRem(ctx, "random_pool:keys:all", key)
			p.redisClient.SRem(ctx, "random_pool:keys:safe", key)
			p.redisClient.SRem(ctx, "random_pool:keys:r18", key)
			p.redisClient.SRem(ctx, "random_pool:keys:portrait_9_16", key)
			p.redisClient.Del(ctx, "random_pool:meta:"+key)
			purged++
		}
	}

	// Recalculate total_bytes
	var newTotal int64
	remainingKeys, _ := p.redisClient.SMembers(ctx, "random_pool:keys:all").Result()
	for _, key := range remainingKeys {
		if metaData, err := p.redisClient.Get(ctx, "random_pool:meta:"+key).Result(); err == nil {
			var meta PoolItemMeta
			if err := json.Unmarshal([]byte(metaData), &meta); err == nil {
				newTotal += meta.Size
			}
		}
	}
	p.redisClient.Set(ctx, "random_pool:total_bytes", newTotal, 0)

	if purged > 0 {
		log.Printf("[Pool] Purged %d non-16:9/4:3 images. Remaining high-res widescreen images: %d (%d MB)",
			purged, len(remainingKeys), newTotal/(1024*1024))
	}
	return purged, nil
}

// GetRandomImage retrieves a random illustration from the local S3 pool.
// If clientIP is provided, tracks views per IP in 24 hours. If an image is randomized
// 3 or more times in 1 day for that IP, it is deleted from S3/Redis and a fresh one is served.
func (p *RandomPool) GetRandomImage(ctx context.Context, allowR18, blockR18 bool, aspect string, clientIP string) (io.ReadCloser, *PoolItemMeta, error) {
	if !p.IsEnabled() {
		return nil, nil, fmt.Errorf("pool not enabled")
	}

	var setName string
	if blockR18 {
		setName = "random_pool:keys:safe"
	} else if allowR18 {
		setName = "random_pool:keys:r18"
	} else {
		setName = "random_pool:keys:all"
	}

	// Retry up to 10 times to pick a matching high-resolution 16:9 / 4:3 item
	for attempt := 0; attempt < 10; attempt++ {
		key, err := p.redisClient.SRandMember(ctx, setName).Result()
		if err != nil || key == "" {
			key, err = p.redisClient.SRandMember(ctx, "random_pool:keys:all").Result()
			if err != nil || key == "" {
				return nil, nil, fmt.Errorf("no images in pool")
			}
		}

		// Retrieve metadata
		metaData, err := p.redisClient.Get(ctx, "random_pool:meta:"+key).Result()
		if err != nil {
			p.redisClient.SRem(ctx, setName, key)
			p.redisClient.SRem(ctx, "random_pool:keys:all", key)
			continue
		}

		var meta PoolItemMeta
		if err := json.Unmarshal([]byte(metaData), &meta); err != nil {
			p.redisClient.SRem(ctx, setName, key)
			p.redisClient.SRem(ctx, "random_pool:keys:all", key)
			continue
		}

		// Strictly require 1:1 square, 4:3, or 16:9 widescreen (ratio 0.95 - 2.6), rejecting 9:16
		if (aspect == "" || aspect == "landscape") && (meta.AspectRatio < 0.95 || meta.AspectRatio > 2.6) {
			p.redisClient.SRem(ctx, setName, key)
			p.redisClient.SRem(ctx, "random_pool:keys:all", key)
			p.redisClient.SRem(ctx, "random_pool:keys:safe", key)
			p.redisClient.SRem(ctx, "random_pool:keys:r18", key)
			continue
		}

		// When blocking R-18 (safe mode default), strictly reject any NSFW item
		if blockR18 && meta.IsR18 {
			p.redisClient.SRem(ctx, "random_pool:keys:safe", key)
			continue
		}

		// Verify size is not a tiny thumbnail (< 150KB)
		if meta.Size < 150*1024 {
			p.redisClient.SRem(ctx, setName, key)
			p.redisClient.SRem(ctx, "random_pool:keys:all", key)
			continue
		}

		// Check 24-hour per-IP repetition limit (3 times in 1 day)
		if clientIP != "" {
			ipViewKey := fmt.Sprintf("random_pool:views:%s:%d", clientIP, meta.IllustID)
			views, _ := p.redisClient.Get(ctx, ipViewKey).Int()
			if views >= 3 {
				// Seen 3+ times today by this IP -> Delete from S3/Redis to recycle pool with new art
				go func(k string, sz int64) {
					delCtx := context.Background()
					p.s3Client.RemoveObject(delCtx, p.bucket, k, minio.RemoveObjectOptions{})
					p.redisClient.SRem(delCtx, "random_pool:keys:all", k)
					p.redisClient.SRem(delCtx, "random_pool:keys:safe", k)
					p.redisClient.SRem(delCtx, "random_pool:keys:r18", k)
					p.redisClient.Del(delCtx, "random_pool:meta:"+k)
					p.redisClient.DecrBy(delCtx, "random_pool:total_bytes", sz)
				}(key, meta.Size)

				// Skip and pick a fresh image
				continue
			}
		}

		obj, err := p.s3Client.GetObject(ctx, p.bucket, key, minio.GetObjectOptions{})
		if err != nil {
			continue
		}

		// Record view count for this client IP with 24-hour expiration
		if clientIP != "" {
			ipViewKey := fmt.Sprintf("random_pool:views:%s:%d", clientIP, meta.IllustID)
			newCount, _ := p.redisClient.Incr(ctx, ipViewKey).Result()
			if newCount == 1 {
				p.redisClient.Expire(ctx, ipViewKey, 24*time.Hour)
			}
			// If this was the 3rd time served to this IP, delete it from S3/Redis
			if newCount >= 3 {
				go func(k string, sz int64) {
					delCtx := context.Background()
					p.s3Client.RemoveObject(delCtx, p.bucket, k, minio.RemoveObjectOptions{})
					p.redisClient.SRem(delCtx, "random_pool:keys:all", k)
					p.redisClient.SRem(delCtx, "random_pool:keys:safe", k)
					p.redisClient.SRem(delCtx, "random_pool:keys:r18", k)
					p.redisClient.Del(delCtx, "random_pool:meta:"+k)
					p.redisClient.DecrBy(delCtx, "random_pool:total_bytes", sz)
				}(key, meta.Size)
			}
		}

		return obj, &meta, nil
	}

	return nil, nil, fmt.Errorf("no matching high-resolution 16:9 / 4:3 images found in pool")
}

// startCrawler periodically populates and maintains the S3 pool
func (p *RandomPool) startCrawler() {
	ticker := time.NewTicker(20 * time.Minute)
	defer ticker.Stop()

	// Run initial sync after a short delay
	time.Sleep(5 * time.Second)
	p.crawlBatch()

	for range ticker.C {
		p.crawlBatch()
	}
}

type candidateArt struct {
	IllustID int
	Title    string
	Author   string
	URL      string
	Width    int64
	Height   int64
	IsR18    bool
}

func (p *RandomPool) saveCandidate(ctx context.Context, item candidateArt, totalBytes *int64) bool {
	if *totalBytes >= p.targetBytes || item.IllustID == 0 || item.URL == "" {
		return false
	}

	w, h := item.Width, item.Height
	if w <= 0 || h <= 0 {
		w, h = 1920, 1080
	}
	aspectRatio := float64(w) / float64(h)

	// Allow 1:1 square, 4:3, and 16:9 widescreen policy: ratio between 0.95 and 2.6
	// Rejects vertical portraits (< 0.95) and 9:16 phone wallpapers (0.56)
	if aspectRatio < 0.95 || aspectRatio > 2.6 {
		return false
	}

	// Check if already in pool
	isMember, _ := p.redisClient.SIsMember(ctx, "random_pool:ids", item.IllustID).Result()
	if isMember {
		return false
	}

	// Download high-res (Original 2K/4K or Master 1200p)
	var body io.ReadCloser
	var contentType string
	var fetchErr error

	for _, candidateURL := range GetHighResCandidateURLs(item.URL) {
		body, contentType, fetchErr = p.pixivClient.ProxyImage(candidateURL)
		if fetchErr == nil && body != nil {
			break
		}
	}

	if body == nil {
		return false
	}

	rawBytes, errRead := io.ReadAll(body)
	body.Close()
	if errRead != nil || len(rawBytes) < 50*1024 {
		return false
	}

	// Optimize & compress to crisp 2K JPEG (quality 82, max 2048px)
	finalBytes, optW, optH, finalContentType, errOpt := OptimizeImageForCache(rawBytes, 2048, 82)
	if errOpt != nil || len(finalBytes) == 0 {
		finalBytes = rawBytes
		finalContentType = contentType
	} else {
		if optW > 0 && optH > 0 {
			w, h = int64(optW), int64(optH)
			aspectRatio = float64(w) / float64(h)
		}
	}

	key := fmt.Sprintf("%d_%d.jpg", item.IllustID, rand.Intn(10000))

	// Store in S3
	_, errPut := p.s3Client.PutObject(ctx, p.bucket, key, bytes.NewReader(finalBytes), int64(len(finalBytes)), minio.PutObjectOptions{
		ContentType: finalContentType,
	})
	if errPut != nil {
		log.Printf("[Pool] Error saving to S3: %v", errPut)
		return false
	}

	meta := PoolItemMeta{
		IllustID:    item.IllustID,
		Title:       item.Title,
		Author:      item.Author,
		ContentType: finalContentType,
		Size:        int64(len(finalBytes)),
		Width:       int(w),
		Height:      int(h),
		AspectRatio: aspectRatio,
		IsR18:       item.IsR18,
		Key:         key,
	}

	metaJSON, _ := json.Marshal(meta)

	// Index in Redis
	pipe := p.redisClient.Pipeline()
	pipe.SAdd(ctx, "random_pool:ids", item.IllustID)
	pipe.SAdd(ctx, "random_pool:keys:all", key)
	if item.IsR18 {
		pipe.SAdd(ctx, "random_pool:keys:r18", key)
	} else {
		pipe.SAdd(ctx, "random_pool:keys:safe", key)
	}
	pipe.Set(ctx, "random_pool:meta:"+key, string(metaJSON), 0)
	pipe.IncrBy(ctx, "random_pool:total_bytes", int64(len(finalBytes)))
	_, _ = pipe.Exec(ctx)

	*totalBytes += int64(len(finalBytes))
	time.Sleep(300 * time.Millisecond) // Polite crawling throttle
	return true
}

func (p *RandomPool) crawlBatch() {
	ctx := context.Background()

	// Check total pool size
	totalBytes, _ := p.redisClient.Get(ctx, "random_pool:total_bytes").Int64()
	if totalBytes >= p.targetBytes {
		return
	}

	// 1. Crawl all popular anime and anime games for high-quality 16:9 / 4:3 wallpapers
	animeGameTags := []string{
		// Anime Games (HoYoverse, Kuro, Yostar, Type-Moon, etc.)
		"原神",                // Genshin Impact
		"GenshinImpact",
		"崩壊:スターレイル",       // Honkai: Star Rail (HSR)
		"HonkaiStarRail",
		"スターレイル",
		"ゼンレスゾーンゼロ",       // Zenless Zone Zero (ZZZ)
		"ZenlessZoneZero",
		"鳴潮",                // Wuthering Waves (WuWa)
		"WutheringWaves",
		"ブルーアーカイブ",        // Blue Archive
		"ブルアカ",
		"アークナイツ",          // Arknights
		"Fate/GrandOrder",    // Fate / FGO
		"FGO",
		"勝利の女神:NIKKE",     // NIKKE
		"ウマ娘プリティーダービー",    // Uma Musume
		"アズールレーン",         // Azur Lane
		"崩壊3rd",             // Honkai Impact 3rd

		// Major Anime & Franchises
		"アニメ",               // General Anime
		"anime",
		"葬送のフリーレン",        // Frieren
		"ぼっち・ざ・ろっく!",      // Bocchi the Rock
		"【推しの子】",           // Oshi no Ko
		"リコリス・リコイル",       // Lycoris Recoil
		"呪術廻戦",             // Jujutsu Kaisen
		"鬼滅の刃",             // Demon Slayer
		"チェンソーマン",          // Chainsaw Man
		"SPY×FAMILY",
		"Re:ゼロから始める異世界生活", // Re:Zero
		"ホロライブ",            // Hololive / VTuber
		"にじさんじ",            // Nijisanji

		// High Quality Scenery & Wallpaper Art
		"風景",                // Anime Scenery / Landscape
		"アニメ背景",            // Anime Backgrounds
		"壁紙",                // Anime Wallpapers
		"女の子",               // Anime Girls
	}

	for _, tag := range animeGameTags {
		if totalBytes >= p.targetBytes {
			break
		}
		for page := 1; page <= 2; page++ {
			if totalBytes >= p.targetBytes {
				break
			}
			res, err := p.pixivClient.SearchIllustsWithMode(tag, page, "safe")
			if err != nil || res == nil || len(res.Illusts) == 0 {
				continue
			}
			for _, illust := range res.Illusts {
				if totalBytes >= p.targetBytes {
					break
				}
				if illust.PageCount > 1 {
					continue // single-page illustrations only
				}
				id, _ := strconv.Atoi(illust.ID)
				if id == 0 {
					continue
				}
				p.saveCandidate(ctx, candidateArt{
					IllustID: id,
					Title:    illust.Title,
					Author:   illust.UserName,
					URL:      illust.Thumbnail,
					Width:    int64(illust.Width),
					Height:   int64(illust.Height),
					IsR18:    illust.IsR18(),
				}, &totalBytes)
			}
		}
	}

	// 2. Crawl trending daily, weekly, monthly rankings
	modes := []string{"daily", "weekly", "monthly", "original", "daily_ai"}
	if p.pixivClient.IsLoggedIn() || p.pixivClient.GetCookie() != "" || p.pixivClient.HasTokens() {
		modes = append(modes, "daily_r18", "weekly_r18")
	}

	for _, mode := range modes {
		if totalBytes >= p.targetBytes {
			break
		}

		res, err := p.pixivClient.GetRankingBatch(mode, 2, "")
		if err != nil || res == nil {
			continue
		}

		for _, item := range res.Contents {
			if totalBytes >= p.targetBytes {
				break
			}

			if item.GetPageCount() > 1 || (item.IllustType != "0" && item.IllustType != "") {
				continue
			}

			illustID := item.GetIllustID()
			if illustID == 0 {
				continue
			}

			w, _ := item.Width.Int64()
			h, _ := item.Height.Int64()
			isR18 := item.IsR18() || strings.Contains(mode, "r18")

			p.saveCandidate(ctx, candidateArt{
				IllustID: illustID,
				Title:    item.Title,
				Author:   item.UserName,
				URL:      item.URL,
				Width:    w,
				Height:   h,
				IsR18:    isR18,
			}, &totalBytes)
		}
	}
}

// PoolStats returns stats about the current S3/Redis random pool
func (p *RandomPool) PoolStats(ctx context.Context) map[string]interface{} {
	if !p.IsEnabled() {
		return map[string]interface{}{"enabled": false}
	}

	totalCount, _ := p.redisClient.SCard(ctx, "random_pool:keys:all").Result()
	safeCount, _ := p.redisClient.SCard(ctx, "random_pool:keys:safe").Result()
	r18Count, _ := p.redisClient.SCard(ctx, "random_pool:keys:r18").Result()
	count916, _ := p.redisClient.SCard(ctx, "random_pool:keys:portrait_9_16").Result()
	totalBytes, _ := p.redisClient.Get(ctx, "random_pool:total_bytes").Int64()

	ratio916 := 0.0
	if totalCount > 0 {
		ratio916 = float64(count916) / float64(totalCount) * 100
	}

	return map[string]interface{}{
		"enabled":             true,
		"total_images":        totalCount,
		"safe_images":         safeCount,
		"r18_images":          r18Count,
		"portrait_9_16_count": count916,
		"portrait_9_16_pct":   fmt.Sprintf("%.1f%%", ratio916),
		"used_mb":             totalBytes / (1024 * 1024),
		"target_mb":           p.targetBytes / (1024 * 1024),
	}
}
