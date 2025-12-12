# Pixiv Image API

A Go-based REST API for fetching images and illustrations from Pixiv.

## Features

- Get illustration details by ID
- Fetch all pages of multi-page illustrations
- Search illustrations by keyword
- Get daily/weekly/monthly rankings
- Proxy Pixiv images (bypasses referer restrictions)
- **OAuth 2.0 authentication** with PKCE (access tokens + refresh tokens)

## Setup

### Prerequisites

- Go 1.21 or later

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `PORT` | Server port (default: 8080) | No |
| `PIXIV_COOKIE` | Your Pixiv session cookie for authenticated requests | No (but recommended) |

### Getting Your Pixiv Cookie

1. Log in to [pixiv.net](https://www.pixiv.net)
2. Open browser developer tools (F12)
3. Go to Application/Storage > Cookies
4. Copy the cookie string (especially `PHPSESSID`)

### Running

```bash
# Set environment variables
$env:PIXIV_COOKIE="your_cookie_here"

# Run the server
go run main.go
```

## API Endpoints

### Health Check
```
GET /health
```

### Get Illustration Details
```
GET /api/illust/{id}
```

Example:
```bash
curl http://localhost:8080/api/illust/12345678
```

### Get Illustration Pages
```
GET /api/illust/{id}/pages
# or
GET /api/illust/{id}?pages=true
```

### Search Illustrations
```
GET /api/search?keyword={keyword}&page={page}
# or
GET /api/search?q={keyword}&page={page}
```

Parameters:
- `keyword` or `q`: Search term (required)
- `page`: Page number (default: 1)

### Get Rankings
```
GET /api/ranking?mode={mode}&page={page}&date={date}
```

Parameters:
- `mode`: Ranking mode (default: "daily")
  - `daily` - Daily ranking
  - `weekly` - Weekly ranking
  - `monthly` - Monthly ranking
  - `rookie` - Rookie ranking
  - `original` - Original works
  - `male` - Male-oriented
  - `female` - Female-oriented
  - `daily_ai` - AI-generated art
- `page`: Page number (default: 1)
- `date`: Specific date in YYYYMMDD format (optional)

### Proxy Image
```
GET /api/image/?url={pixiv_image_url}
# or
GET /api/image/i.pximg.net/...
```

This endpoint proxies images from Pixiv's image servers, adding the required Referer header.

### Authentication

#### Set OAuth Tokens
```
POST /api/auth/token
Content-Type: application/json

{
  "access_token": "your_access_token",
  "refresh_token": "your_refresh_token"
}
```

#### Exchange Authorization Code
```
POST /api/auth/code
Content-Type: application/json

{
  "code": "authorization_code_from_pixiv",
  "code_verifier": "your_pkce_code_verifier"
}
```

#### Refresh Access Token
```
POST /api/auth/refresh
```

#### Check Auth Status
```
GET /api/auth/status
```

Returns:
```json
{
  "logged_in": true,
  "has_cookie": false,
  "has_access_token": true,
  "has_refresh_token": true
}
```
## Response Format

### Success Response
```json
{
  "error": false,
  "data": { ... }
}
```

### Error Response
```json
{
  "error": true,
  "message": "Error description"
}
```

## Examples

### Get illustration info
```bash
curl "http://localhost:8080/api/illust/100000000"
```

### Search for illustrations
```bash
curl "http://localhost:8080/api/search?keyword=landscape&page=1"
```

### Get daily ranking
```bash
curl "http://localhost:8080/api/ranking?mode=daily"
```

### Proxy an image
```bash
curl "http://localhost:8080/api/image/?url=https://i.pximg.net/img-master/img/2024/01/01/00/00/00/12345678_p0_master1200.jpg"
```

## License

MIT
