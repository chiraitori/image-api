package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/redis/go-redis/v9"
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

	// Start background crawler to maintain the ~5GB cache
	go Pool.startCrawler()
}

// IsEnabled returns true if pool is operational
func (p *RandomPool) IsEnabled() bool {
	return p != nil && p.enabled
}

// GetRandomImage retrieves a random illustration from the local S3 pool
func (p *RandomPool) GetRandomImage(ctx context.Context, allowR18, blockR18 bool) (io.ReadCloser, *PoolItemMeta, error) {
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

	key, err := p.redisClient.SRandMember(ctx, setName).Result()
	if err != nil || key == "" {
		// Fallback to all if specific set is empty
		key, err = p.redisClient.SRandMember(ctx, "random_pool:keys:all").Result()
		if err != nil || key == "" {
			return nil, nil, fmt.Errorf("no images in pool")
		}
	}

	// Retrieve metadata
	metaData, err := p.redisClient.Get(ctx, "random_pool:meta:"+key).Result()
	if err != nil {
		return nil, nil, fmt.Errorf("missing metadata for key %s: %w", key, err)
	}

	var meta PoolItemMeta
	if err := json.Unmarshal([]byte(metaData), &meta); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	obj, err := p.s3Client.GetObject(ctx, p.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get S3 object: %w", err)
	}

	return obj, &meta, nil
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

func (p *RandomPool) crawlBatch() {
	ctx := context.Background()

	// Check total pool size
	totalBytes, _ := p.redisClient.Get(ctx, "random_pool:total_bytes").Int64()
	if totalBytes >= p.targetBytes {
		return
	}

	// Modes to pull high-quality pictures from
	modes := []string{"daily", "weekly", "monthly", "rookie", "original", "daily_ai"}
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

			// Single illustrations only
			if item.GetPageCount() > 1 || (item.IllustType != "0" && item.IllustType != "") {
				continue
			}

			illustID := item.GetIllustID()
			if illustID == 0 {
				continue
			}

			// Check if already downloaded
			isMember, _ := p.redisClient.SIsMember(ctx, "random_pool:ids", illustID).Result()
			if isMember {
				continue
			}

			w, _ := item.Width.Int64()
			h, _ := item.Height.Int64()
			if w == 0 || h == 0 {
				w, h = 1200, 1200
			}
			aspectRatio := float64(w) / float64(h)

			// Aspect Ratio Policy: Don't too much 9:16 (aspect ratio < 0.65)
			// Limit 9:16 portrait images to max 15% of the total pool
			if aspectRatio < 0.65 {
				count916, _ := p.redisClient.SCard(ctx, "random_pool:keys:portrait_9_16").Result()
				totalCount, _ := p.redisClient.SCard(ctx, "random_pool:keys:all").Result()
				if totalCount > 20 && float64(count916)/float64(totalCount) > 0.15 {
					continue // Skip excess 9:16 tall wallpapers
				}
			}

			// Download illustration
			imageURL := item.URL
			if imageURL == "" {
				continue
			}
			// Attempt to fetch regular / large quality
			regularURL := strings.Replace(imageURL, "c/240x480/", "", 1)
			regularURL = strings.Replace(regularURL, "c/540x540_70/", "", 1)
			regularURL = strings.Replace(regularURL, "custom-thumb/", "", 1)

			body, contentType, err := p.pixivClient.ProxyImage(regularURL)
			if err != nil {
				body, contentType, err = p.pixivClient.ProxyImage(item.URL)
				if err != nil {
					continue
				}
			}

			imgBytes, errRead := io.ReadAll(body)
			body.Close()
			if errRead != nil || len(imgBytes) == 0 {
				continue
			}

			ext := ".jpg"
			if strings.Contains(contentType, "png") {
				ext = ".png"
			} else if strings.Contains(contentType, "gif") {
				ext = ".gif"
			} else if strings.Contains(contentType, "webp") {
				ext = ".webp"
			}

			key := fmt.Sprintf("%d_%d%s", illustID, rand.Intn(10000), ext)

			// Store in S3
			_, errPut := p.s3Client.PutObject(ctx, p.bucket, key, bytes.NewReader(imgBytes), int64(len(imgBytes)), minio.PutObjectOptions{
				ContentType: contentType,
			})
			if errPut != nil {
				log.Printf("[Pool] Error saving to S3: %v", errPut)
				continue
			}

			isR18 := item.IsR18() || strings.Contains(mode, "r18")

			meta := PoolItemMeta{
				IllustID:    illustID,
				Title:       item.Title,
				Author:      item.UserName,
				ContentType: contentType,
				Size:        int64(len(imgBytes)),
				Width:       int(w),
				Height:      int(h),
				AspectRatio: aspectRatio,
				IsR18:       isR18,
				Key:         key,
			}

			metaJSON, _ := json.Marshal(meta)

			// Index in Redis
			pipe := p.redisClient.Pipeline()
			pipe.SAdd(ctx, "random_pool:ids", illustID)
			pipe.SAdd(ctx, "random_pool:keys:all", key)
			if isR18 {
				pipe.SAdd(ctx, "random_pool:keys:r18", key)
			} else {
				pipe.SAdd(ctx, "random_pool:keys:safe", key)
			}
			if aspectRatio < 0.65 {
				pipe.SAdd(ctx, "random_pool:keys:portrait_9_16", key)
			}
			pipe.Set(ctx, "random_pool:meta:"+key, string(metaJSON), 0)
			pipe.IncrBy(ctx, "random_pool:total_bytes", int64(len(imgBytes)))
			_, _ = pipe.Exec(ctx)

			totalBytes += int64(len(imgBytes))
			time.Sleep(300 * time.Millisecond) // Polite crawling throttle
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
