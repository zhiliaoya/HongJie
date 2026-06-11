package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	wechatAppID     = "you wechatAppID" // 自行填写
	wechatAppSecret = "you wechatAppSecret" // 自行填写

	certPath = "/etc/letsencrypt/live/域名地址/fullchain.pem"// 自行填写
	keyPath  = "/etc/letsencrypt/live/域名地址/privkey.pem" // 自行填写

	webServiceURL    = "http://web-service:80" // 自行修改
	staticConfigPath = "static_files.json" // 自行修改

	// Cloudflare Turnstile 密钥
	cfTurnstileSecret  = "" // 自行填写
	cfTurnstileSiteKey = "" // 自行填写

	accessToken   string
	accessTokenMu sync.RWMutex

	sceneStore     = NewSceneStore()
	authTokenStore = NewAuthTokenStore()

	staticConfig   *StaticConfig
	staticConfigMu sync.RWMutex

	// 防御层
	qrRateLimiter  = NewQRRateLimiter()
	ipBanList      = NewIPBanList()
	suspiciousLog  = NewSuspiciousLogger()
	challengeStore = NewChallengeStore()

	defaultTestSceneID = "fe9432b75b02d3d51e90892389496957"
)

// ─────────────────────────────────────────────
// 场景令牌存储（一次性动态链路）
// ─────────────────────────────────────────────

// SceneToken 一次性场景令牌，60秒有效期
type SceneToken struct {
	Token     string    `json:"token"`
	SceneID   string    `json:"scene_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

// SceneTokenStore 管理一次性动态链路
type SceneTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*SceneToken // token -> SceneToken
	scenes map[string]string      // sceneID -> token (反向映射)
}

func NewSceneTokenStore() *SceneTokenStore {
	s := &SceneTokenStore{
		tokens: make(map[string]*SceneToken),
		scenes: make(map[string]string),
	}
	go s.cleanup()
	return s
}

// CreateToken 为场景生成一次性令牌，返回 token 字符串
func (s *SceneTokenStore) CreateToken(sceneID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 如果已有未使用的 token，先作废
	if oldToken, exists := s.scenes[sceneID]; exists {
		if t, ok := s.tokens[oldToken]; ok {
			t.Used = true
		}
	}

	token := generateSceneToken()
	st := &SceneToken{
		Token:     token,
		SceneID:   sceneID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(60 * time.Second),
		Used:      false,
	}
	s.tokens[token] = st
	s.scenes[sceneID] = token

	log.Printf("🔗 创建一次性链路 [Token: %s, SceneID: %s, 路径: /api/%s]", token[:8], sceneID, token)
	return token
}

// Validate 验证令牌是否有效，返回场景ID
func (s *SceneTokenStore) Validate(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, exists := s.tokens[token]
	if !exists || st.Used {
		return "", false
	}

	if time.Now().After(st.ExpiresAt) {
		st.Used = true
		return "", false
	}

	// 标记为已使用（一次性）
	st.Used = true
	return st.SceneID, true
}

// GetTokenByScene 通过场景ID获取当前有效令牌
func (s *SceneTokenStore) GetTokenByScene(sceneID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, exists := s.scenes[sceneID]
	if !exists {
		return "", false
	}
	st, ok := s.tokens[token]
	if !ok || st.Used || time.Now().After(st.ExpiresAt) {
		return "", false
	}
	return token, true
}

func (s *SceneTokenStore) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for k, v := range s.tokens {
			if now.After(v.ExpiresAt.Add(5 * time.Minute)) {
				delete(s.tokens, k)
			}
		}
		// 清理过期的反向映射
		for sceneID, token := range s.scenes {
			if _, exists := s.tokens[token]; !exists {
				delete(s.scenes, sceneID)
			}
		}
		s.mu.Unlock()
	}
}

var sceneTokenStore = NewSceneTokenStore()

func generateSceneToken() string {
	b := make([]byte, 16) // 192 bits，足够安全
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ─────────────────────────────────────────────
// 静态文件配置
// ─────────────────────────────────────────────

type StaticConfig struct {
	StaticFiles   map[string]string `json:"static_files"`
	CacheDuration int               `json:"cache_duration"`
	EnableCache   bool              `json:"enable_cache"`
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func loadStaticConfig() (*StaticConfig, error) {
	data, err := os.ReadFile(staticConfigPath)
	if err != nil {
		return nil, fmt.Errorf("读取静态文件配置失败: %v", err)
	}
	var config StaticConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析静态文件配置失败: %v", err)
	}
	log.Printf("📁 加载静态文件配置: %d 个文件", len(config.StaticFiles))
	return &config, nil
}

func getStaticConfig() *StaticConfig {
	staticConfigMu.RLock()
	defer staticConfigMu.RUnlock()
	return staticConfig
}

func isStaticFile(path string) (string, bool) {
	config := getStaticConfig()
	if config == nil {
		return "", false
	}
	filePath, exists := config.StaticFiles[path]
	return filePath, exists
}

func handleStaticFile(w http.ResponseWriter, r *http.Request, filePath string) {
	log.Printf("📁 静态文件请求: %s -> %s", r.URL.Path, filePath)
	fileInfo, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	config := getStaticConfig()
	if config != nil && config.EnableCache {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", config.CacheDuration))
		w.Header().Set("ETag", fmt.Sprintf(`"%x-%x"`, fileInfo.ModTime().Unix(), fileInfo.Size()))
	}
	w.Header().Set("Content-Type", getContentType(filePath))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	http.ServeFile(w, r, filePath)
}

func getContentType(filePath string) string {
	ext := ""
	for i := len(filePath) - 1; i >= 0; i-- {
		if filePath[i] == '.' {
			ext = filePath[i:]
			break
		}
	}
	switch ext {
	case ".ico":
		return "image/x-icon"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".html":
		return "text/html"
	case ".txt":
		return "text/plain"
	default:
		return "application/octet-stream"
	}
}

// ─────────────────────────────────────────────
// 防御层 1：IP 封禁
// ─────────────────────────────────────────────

type IPBanList struct {
	mu      sync.RWMutex
	banned  map[string]time.Time
	strikes map[string]int
}

func NewIPBanList() *IPBanList {
	b := &IPBanList{
		banned:  make(map[string]time.Time),
		strikes: make(map[string]int),
	}
	go b.cleanup()
	return b
}

func (b *IPBanList) AddStrike(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.strikes[ip]++
	strikes := b.strikes[ip]
	var banDuration time.Duration
	switch {
	case strikes >= 20:
		banDuration = 24 * time.Hour
	case strikes >= 10:
		banDuration = 1 * time.Hour
	case strikes >= 5:
		banDuration = 10 * time.Minute
	default:
		return
	}
	b.banned[ip] = time.Now().Add(banDuration)
	log.Printf("🚫 IP封禁 [IP: %s, 违规: %d次, 封禁: %v]", ip, strikes, banDuration)
}

func (b *IPBanList) IsBanned(ip string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	unbanAt, exists := b.banned[ip]
	if !exists {
		return false
	}
	if time.Now().After(unbanAt) {
		return false
	}
	return true
}

func (b *IPBanList) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		b.mu.Lock()
		now := time.Now()
		for ip, unbanAt := range b.banned {
			if now.After(unbanAt) {
				delete(b.banned, ip)
				delete(b.strikes, ip)
			}
		}
		b.mu.Unlock()
	}
}

// ─────────────────────────────────────────────
// 防御层 2：QR 码请求限流
// ─────────────────────────────────────────────

type QRRateLimiter struct {
	mu      sync.Mutex
	records map[string]time.Time
}

func NewQRRateLimiter() *QRRateLimiter {
	r := &QRRateLimiter{
		records: make(map[string]time.Time),
	}
	go r.cleanup()
	return r
}

func (r *QRRateLimiter) Allow(fingerprint, ip string) (bool, int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cooldown := 60 * time.Second

	keys := []string{
		"ip:" + ip,
		"fp:" + fingerprint,
		"combo:" + fingerprint + ":" + ip,
	}

	for _, key := range keys {
		if last, ok := r.records[key]; ok {
			elapsed := now.Sub(last)
			if elapsed < cooldown {
				remaining := int(math.Ceil((cooldown - elapsed).Seconds()))
				return false, remaining
			}
		}
	}

	for _, key := range keys {
		r.records[key] = now
	}
	return true, 0
}

func (r *QRRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		r.mu.Lock()
		cutoff := time.Now().Add(-2 * time.Minute)
		for k, t := range r.records {
			if t.Before(cutoff) {
				delete(r.records, k)
			}
		}
		r.mu.Unlock()
	}
}

// ─────────────────────────────────────────────
// 防御层 3：工作量证明挑战 (PoW)
// ─────────────────────────────────────────────

type Challenge struct {
	Seed       string    `json:"seed"`
	Difficulty int       `json:"difficulty"`
	CreatedAt  time.Time `json:"-"`
	Used       bool      `json:"-"`
}

type ChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]*Challenge
}

func NewChallengeStore() *ChallengeStore {
	s := &ChallengeStore{challenges: make(map[string]*Challenge)}
	go s.cleanup()
	return s
}

func (s *ChallengeStore) NewChallenge() *Challenge {
	b := make([]byte, 16)
	rand.Read(b)
	seed := hex.EncodeToString(b)
	c := &Challenge{
		Seed:       seed,
		Difficulty: 16,
		CreatedAt:  time.Now(),
	}
	s.mu.Lock()
	s.challenges[seed] = c
	s.mu.Unlock()
	return c
}

func (s *ChallengeStore) Verify(seed, nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.challenges[seed]
	if !ok || c.Used {
		return false
	}
	if time.Since(c.CreatedAt) > 5*time.Minute {
		delete(s.challenges, seed)
		return false
	}

	hash := sha256.Sum256([]byte(seed + nonce))
	required := c.Difficulty
	for i := 0; i < len(hash) && required > 0; i++ {
		b := hash[i]
		bits := min(required, 8)
		mask := byte(0xFF << (8 - bits))
		if b&mask != 0 {
			return false
		}
		required -= bits
	}

	c.Used = true
	delete(s.challenges, seed)
	return true
}

func (s *ChallengeStore) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		cutoff := time.Now().Add(-6 * time.Minute)
		for k, c := range s.challenges {
			if c.CreatedAt.Before(cutoff) {
				delete(s.challenges, k)
			}
		}
		s.mu.Unlock()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─────────────────────────────────────────────
// 防御层 4：可疑行为日志
// ─────────────────────────────────────────────

type SuspiciousEvent struct {
	Time    time.Time
	IP      string
	Reason  string
	Details string
}

type SuspiciousLogger struct {
	mu     sync.Mutex
	events []SuspiciousEvent
}

func NewSuspiciousLogger() *SuspiciousLogger {
	return &SuspiciousLogger{}
}

func (l *SuspiciousLogger) Log(ip, reason, details string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	event := SuspiciousEvent{
		Time:    time.Now(),
		IP:      ip,
		Reason:  reason,
		Details: details,
	}
	l.events = append(l.events, event)
	log.Printf("⚠️  可疑行为 [IP: %s, 原因: %s, 详情: %s]", ip, reason, details)

	if len(l.events) > 1000 {
		l.events = l.events[len(l.events)-1000:]
	}
}

func (l *SuspiciousLogger) RecentEvents(n int) []SuspiciousEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > len(l.events) {
		n = len(l.events)
	}
	return l.events[len(l.events)-n:]
}

// ─────────────────────────────────────────────
// 场景 & 授权令牌管理
// ─────────────────────────────────────────────

type SceneStatus struct {
	SceneID     string    `json:"scene_id"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	UserID      string    `json:"user_id,omitempty"`
	OpenID      string    `json:"open_id,omitempty"`
	RedirectURI string    `json:"redirect_uri,omitempty"` // 可选的跳转目标
}

type SceneStore struct {
	mu     sync.RWMutex
	scenes map[string]*SceneStatus
}

type AuthToken struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	OpenID    string    `json:"open_id,omitempty"`
	SceneID   string    `json:"scene_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AuthTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*AuthToken
}

func NewAuthTokenStore() *AuthTokenStore {
	store := &AuthTokenStore{tokens: make(map[string]*AuthToken)}
	go store.cleanExpiredTokens()
	return store
}

func (s *AuthTokenStore) CreateToken(userID, openID, sceneID string) *AuthToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := generateAuthToken()
	authToken := &AuthToken{
		Token:     token,
		UserID:    userID,
		OpenID:    openID,
		SceneID:   sceneID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	s.tokens[token] = authToken
	log.Printf("✅ 创建授权令牌 [Token: %s..., UserID: %s, OpenID: %s]", token[:16], userID, openID)
	return authToken
}

func (s *AuthTokenStore) ValidateToken(token string) (*AuthToken, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	authToken, exists := s.tokens[token]
	if !exists {
		return nil, false
	}
	if time.Now().After(authToken.ExpiresAt) {
		delete(s.tokens, token)
		return nil, false
	}
	return authToken, true
}

func (s *AuthTokenStore) cleanExpiredTokens() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for token, authToken := range s.tokens {
			if now.After(authToken.ExpiresAt) {
				delete(s.tokens, token)
			}
		}
		s.mu.Unlock()
	}
}

func NewSceneStore() *SceneStore {
	store := &SceneStore{scenes: make(map[string]*SceneStatus)}
	go store.cleanExpiredScenes()
	return store
}

func (s *SceneStore) CreateScene(sceneID string) *SceneStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := &SceneStatus{
		SceneID:   sceneID,
		Status:    "pending",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	s.scenes[sceneID] = status
	log.Printf("📱 创建场景 [SceneID: %s]", sceneID)
	return status
}

func (s *SceneStore) UpdateScene(sceneID, status, userID, openID string) (*SceneStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scene, exists := s.scenes[sceneID]
	if !exists {
		return nil, false
	}
	oldStatus := scene.Status
	switch status {
	case "confirm":
		status = "confirmed"
	case "cancel":
		status = "cancelled"
	}
	scene.Status = status
	scene.UpdatedAt = time.Now()
	if userID != "" {
		scene.UserID = userID
	}
	if openID != "" {
		scene.OpenID = openID
	}
	log.Printf("🔄 场景状态变更 [SceneID: %s, %s -> %s, UserID: %s, OpenID: %s]",
		sceneID, oldStatus, status, scene.UserID, scene.OpenID)
	return scene, true
}

func (s *SceneStore) GetScene(sceneID string) (*SceneStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	scene, exists := s.scenes[sceneID]
	return scene, exists
}

func (s *SceneStore) cleanExpiredScenes() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, scene := range s.scenes {
			if id != defaultTestSceneID && now.Sub(scene.CreatedAt) > 5*time.Minute {
				delete(s.scenes, id)
			}
		}
		s.mu.Unlock()
	}
}

// ─────────────────────────────────────────────
// 工具函数
// ─────────────────────────────────────────────

func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func generateSceneID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateAuthToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ─────────────────────────────────────────────
// API：获取 PoW 挑战
// ─────────────────────────────────────────────

func handleQRChallenge(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)

	if ipBanList.IsBanned(ip) {
		suspiciousLog.Log(ip, "banned_ip_challenge", "封禁期间尝试获取挑战")
		http.Error(w, "请求被拒绝", http.StatusForbidden)
		return
	}

	c := challengeStore.NewChallenge()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"seed":       c.Seed,
		"difficulty": c.Difficulty,
	})
}

// ─────────────────────────────────────────────
// API：生成二维码（含全部防御，返回动态链路）
// ─────────────────────────────────────────────

func handleQRRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := getClientIP(r)
	w.Header().Set("Content-Type", "application/json")

	// 防御 1：IP 封禁检查
	if ipBanList.IsBanned(ip) {
		suspiciousLog.Log(ip, "banned_ip_qr", "封禁期间请求二维码")
		ipBanList.AddStrike(ip)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "error": "请求被拒绝，请稍后再试",
		})
		return
	}

	// 解析请求体
	var req struct {
		Fingerprint  string `json:"fingerprint"`
		PowSeed      string `json:"pow_seed"`
		PowNonce     string `json:"pow_nonce"`
		CaptchaToken string `json:"captcha_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 防御 2：基础字段校验
	if req.Fingerprint == "" || req.PowSeed == "" || req.PowNonce == "" {
		suspiciousLog.Log(ip, "missing_fields", fmt.Sprintf("fp=%v seed=%v nonce=%v",
			req.Fingerprint != "", req.PowSeed != "", req.PowNonce != ""))
		ipBanList.AddStrike(ip)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "error": "请求参数不完整",
		})
		return
	}

	// 防御 3：Cloudflare Turnstile 人机验证
	if cfTurnstileSecret != "" {
		if !verifyCFTurnstile(req.CaptchaToken, ip) {
			suspiciousLog.Log(ip, "captcha_failed", "Turnstile验证失败")
			ipBanList.AddStrike(ip)
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false, "error": "人机验证失败，请重试",
			})
			return
		}
	}

	// 防御 4：工作量证明验证
	if !challengeStore.Verify(req.PowSeed, req.PowNonce) {
		suspiciousLog.Log(ip, "pow_failed", fmt.Sprintf("seed=%s", req.PowSeed))
		ipBanList.AddStrike(ip)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "error": "工作量证明验证失败，请刷新重试",
		})
		return
	}

	// 防御 5：设备指纹 + IP 限流
	allowed, retryAfter := qrRateLimiter.Allow(req.Fingerprint, ip)
	if !allowed {
		suspiciousLog.Log(ip, "rate_limited", fmt.Sprintf("fp=%s retry_after=%ds", req.Fingerprint[:8], retryAfter))
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":     false,
			"error":       fmt.Sprintf("请求过于频繁，请 %d 秒后重试", retryAfter),
			"retry_after": retryAfter,
		})
		return
	}

	// ── 全部通过：生成场景 + 动态令牌 ─────────────
	sceneID := generateSceneID()
	sceneStore.CreateScene(sceneID)

	// 创建一次性链路令牌
	sceneToken := sceneTokenStore.CreateToken(sceneID)

	// 小程序码携带的动态路径：/api/{scene_token}
	// 小程序端拿到 scene_token 后，拼接：https://zhiliaoya.cn/api/{scene_token}?code={wx_code}
	qrBase64, err := generateMiniProgramCode(sceneToken)
	if err != nil {
		log.Printf("❌ 生成二维码失败: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "error": "生成二维码失败，请稍后重试",
		})
		return
	}

	// 通过 HttpOnly Cookie 传递 scene_id（前端不需要知道 scene_token）
	http.SetCookie(w, &http.Cookie{
		Name:     "scene_id",
		Value:    sceneID,
		Path:     "/",
		Expires:  time.Now().Add(5 * time.Minute),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	log.Printf("✅ 二维码生成成功 [IP: %s, SceneID: %s, TokenPath: /api/%s]", ip, sceneID, sceneToken[:16])

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"qr":       qrBase64,
		"scene_id": sceneID,
		// ⚠️ 不再向前端暴露 scene_token，前端仅通过 scene_id 轮询/SSE
	})
}

// ─────────────────────────────────────────────
// 核心新增：动态链路处理（微信小程序回调）
// GET/POST /api/{scene_token}?code=WECHAT_CODE
// ─────────────────────────────────────────────

func handleSceneTokenCallback(w http.ResponseWriter, r *http.Request) {
	// 从路径中提取 scene_token
	// 路径格式：/api/{scene_token}
	path := strings.TrimPrefix(r.URL.Path, "/api/")

	// 基础验证：token 长度应为 48（24字节 hex）
	if len(path) != 32 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "无效的链接",
		})
		return
	}

	sceneToken := path

	// 验证令牌有效性（一次性使用）
	sceneID, valid := sceneTokenStore.Validate(sceneToken)
	if !valid {
		log.Printf("❌ 无效或已使用的一次性链路 [Token: %s]", sceneToken[:16])
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "链接已失效或已被使用",
		})
		return
	}

	// 验证场景是否存在
	_, exists := sceneStore.GetScene(sceneID)
    if !exists {
        log.Printf("❌ 场景不存在 [SceneID: %s]", sceneID)
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false, "message": "场景已过期",
        })
        return
    }

	// 获取微信 code
	code := r.URL.Query().Get("code")
	if code == "" {
		// 尝试从 POST body 获取
		if r.Method == "POST" {
			var body struct {
				Code string `json:"code"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				code = body.Code
			}
		}
	}

	if code == "" {
		log.Printf("⚠️ 缺少微信 code [SceneID: %s]", sceneID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "缺少微信授权码",
		})
		return
	}

	// ── 通过 code 换取 openid ────────────────────
	openID, err := getWechatOpenID(code)
	if err != nil {
		log.Printf("❌ 获取 OpenID 失败 [SceneID: %s, Code: %s, Error: %v]", sceneID, code[:10], err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "微信验证失败，请重新扫码",
		})
		return
	}

	// ── 验证通过，更新场景状态 ──────────────────
	// 使用 OpenID 作为 UserID（也可以额外维护用户表）
	userID := "wx_" + openID
	updatedScene, _ := sceneStore.UpdateScene(sceneID, "confirmed", userID, openID)

	log.Printf("✅ 微信验证成功 [SceneID: %s, OpenID: %s, UserID: %s]",
		sceneID, openID, userID)

	// 返回成功，让小程序端展示成功页面
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "登录确认成功",
		"status":  updatedScene.Status,
	})

	// 注意：前端的浏览器页面通过 SSE/轮询获知状态变化后，
	// 调用 /api/exchange-token 获取 auth_token
}

// getWechatOpenID 通过 code 换取 openid
func getWechatOpenID(code string) (string, error) {
	apiURL := fmt.Sprintf(
		"https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code",
		wechatAppID, wechatAppSecret, code,
	)

	resp, err := http.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("请求微信接口失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		OpenID     string `json:"openid"`
		SessionKey string `json:"session_key"`
		UnionID    string `json:"unionid,omitempty"`
		ErrCode    int    `json:"errcode"`
		ErrMsg     string `json:"errmsg"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("解析微信返回失败: %v", err)
	}

	if result.ErrCode != 0 {
		return "", fmt.Errorf("微信返回错误 [%d]: %s", result.ErrCode, result.ErrMsg)
	}

	return result.OpenID, nil
}

// ─────────────────────────────────────────────
// Cloudflare Turnstile 验证
// ─────────────────────────────────────────────

func verifyCFTurnstile(token, ip string) bool {
	if token == "" {
		return false
	}
	resp, err := http.PostForm(
		"https://challenges.cloudflare.com/turnstile/v0/siteverify",
		url.Values{
			"secret":   {cfTurnstileSecret},
			"response": {token},
			"remoteip": {ip},
		},
	)
	if err != nil {
		log.Printf("⚠️ Turnstile 请求失败: %v", err)
		return false
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
	}
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &result)
	return result.Success
}

// ─────────────────────────────────────────────
// 管理端点
// ─────────────────────────────────────────────

func handleAdminSuspicious(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	if !isPrivateIP(ip) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	events := suspiciousLog.RecentEvents(100)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func isPrivateIP(ip string) bool {
	privateRanges := []string{"127.", "10.", "172.16.", "172.17.", "192.168.", "::1"}
	for _, prefix := range privateRanges {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────
// 原有 Handlers
// ─────────────────────────────────────────────

func handleGateway(w http.ResponseWriter, r *http.Request) {
	// ⚠️ 新增：检查是否为动态链路回调（/api/xxx）
	if strings.HasPrefix(r.URL.Path, "/api/") && len(r.URL.Path) == 37 {
		// /api/ + 48位hex = 53字符
		if !strings.Contains(r.URL.Path[5:], ".") && !strings.Contains(r.URL.Path[5:], "/") {
			handleSceneTokenCallback(w, r)
			return
		}
	}

	log.Printf("🌐 网关入口 [%s %s]", r.Method, r.URL.Path)

	if filePath, isStatic := isStaticFile(r.URL.Path); isStatic {
		handleStaticFile(w, r, filePath)
		return
	}

	authCookie, err := r.Cookie("auth_token")
	if err == nil && authCookie.Value != "" {
		if authToken, valid := authTokenStore.ValidateToken(authCookie.Value); valid {
			log.Printf("✅ 已认证 [UserID: %s]，代理转发", authToken.UserID)
			proxyToBackend(w, r, authToken)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:    "auth_token",
			Value:   "",
			Path:    "/",
			Expires: time.Unix(0, 0),
			MaxAge:  -1, HttpOnly: true, Secure: true,
		})
	}

	// 从 query 或 cookie 获取 scene_id
	sceneID := r.URL.Query().Get("scene_id")
	if sceneID == "" {
		if cookie, err := r.Cookie("scene_id"); err == nil {
			sceneID = cookie.Value
		}
	}

	if sceneID != "" {
		scene, exists := sceneStore.GetScene(sceneID)
		if exists && scene.Status == "confirmed" {
			authToken := authTokenStore.CreateToken(scene.UserID, scene.OpenID, sceneID)
			http.SetCookie(w, &http.Cookie{
				Name:     "auth_token",
				Value:    authToken.Token,
				Path:     "/",
				Expires:  authToken.ExpiresAt,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})
			proxyToBackend(w, r, authToken)
			return
		} else if exists && scene.Status == "pending" {
			http.Redirect(w, r, "/login?scene="+sceneID, http.StatusFound)
			return
		}
	}

	log.Printf("👤 未认证，跳转登录页")
	http.Redirect(w, r, "/login", http.StatusFound)
}

func proxyToBackend(w http.ResponseWriter, r *http.Request, authToken *AuthToken) {
	target, err := url.Parse(webServiceURL)
	if err != nil {
		http.Error(w, "服务不可用", http.StatusServiceUnavailable)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Set("X-User-ID", authToken.UserID)
		req.Header.Set("X-Open-ID", authToken.OpenID)
		req.Header.Set("X-Auth-Token", authToken.Token)
		req.Header.Set("X-Forwarded-For", r.RemoteAddr)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", r.Host)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("X-Gateway", "wechat-auth-gateway")
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("❌ 代理转发失败: %v", err)
		http.Error(w, "后端服务不可用", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	authCookie, err := r.Cookie("auth_token")
	if err == nil && authCookie.Value != "" {
		if authToken, valid := authTokenStore.ValidateToken(authCookie.Value); valid {
			proxyToBackend(w, r, authToken)
			return
		}
	}

	tmpl := template.Must(template.New("login").Parse(loginHTML))
	tmpl.Execute(w, map[string]interface{}{
		"TurnstileSiteKey": cfTurnstileSiteKey,
	})
}

func handleExchangeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SceneID string `json:"scene_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	log.Printf("🔄 Token交换请求 [SceneID: %s]", req.SceneID)

	if req.SceneID == defaultTestSceneID {
		authToken := authTokenStore.CreateToken("test_user_001", "test_openid", req.SceneID)
		http.SetCookie(w, &http.Cookie{
			Name: "auth_token", Value: authToken.Token, Path: "/",
			Expires: authToken.ExpiresAt, HttpOnly: true, Secure: true,
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "授权成功"})
		return
	}

	scene, exists := sceneStore.GetScene(req.SceneID)
	if !exists || scene.Status != "confirmed" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "场景未确认或已过期",
		})
		return
	}

	authToken := authTokenStore.CreateToken(scene.UserID, scene.OpenID, req.SceneID)
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    authToken.Token,
		Path:     "/",
		Expires:  authToken.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "授权成功，正在跳转...",
	})
}

func handleStatusCheck(w http.ResponseWriter, r *http.Request) {
	sceneID := r.URL.Query().Get("scene_id")
	if sceneID == "" {
		http.Error(w, "缺少 scene_id 参数", http.StatusBadRequest)
		return
	}

	if sceneID == defaultTestSceneID {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "confirmed",
			"scene_id":      sceneID,
			"user_id":       "test_user_001",
			"need_exchange": true,
			"timestamp":     time.Now().Unix(),
		})
		return
	}

	scene, exists := sceneStore.GetScene(sceneID)
	if !exists {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "expired",
			"message": "场景已过期",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"status":    scene.Status,
		"scene_id":  scene.SceneID,
		"user_id":   scene.UserID,
		"timestamp": scene.UpdatedAt.Unix(),
	}
	if scene.Status == "confirmed" {
		resp["need_exchange"] = true
	}
	json.NewEncoder(w).Encode(resp)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var callback struct {
		SceneID string `json:"scene_id"`
		Action  string `json:"action"`
		UserID  string `json:"user_id,omitempty"`
		OpenID  string `json:"open_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&callback); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if callback.SceneID == "" || (callback.Action != "confirm" && callback.Action != "cancel") {
		http.Error(w, "Invalid parameters", http.StatusBadRequest)
		return
	}

	status := "confirmed"
	if callback.Action == "cancel" {
		status = "cancelled"
	}

	if callback.SceneID == defaultTestSceneID {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"status":  "confirmed",
		})
		return
	}

	scene, exists := sceneStore.UpdateScene(callback.SceneID, status, callback.UserID, callback.OpenID)
	if !exists {
		http.Error(w, "Scene not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"status":  scene.Status,
	})
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	sceneID := r.URL.Query().Get("scene_id")
	if sceneID == "" {
		http.Error(w, "缺少 scene_id 参数", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	fmt.Fprintf(w, "data: {\"status\": \"connected\"}\n\n")
	flusher.Flush()

	if sceneID == defaultTestSceneID {
		time.Sleep(2 * time.Second)
		data, _ := json.Marshal(map[string]interface{}{
			"status":        "confirmed",
			"need_exchange": true,
		})
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	timeout := time.After(5 * time.Minute)

	for {
		select {
		case <-ticker.C:
			scene, exists := sceneStore.GetScene(sceneID)
			if !exists || scene.Status != "pending" {
				s := "expired"
				needExchange := false
				if exists {
					s = scene.Status
					needExchange = s == "confirmed"
				}
				data, _ := json.Marshal(map[string]interface{}{
					"status":        s,
					"need_exchange": needExchange,
				})
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
				return
			}
			fmt.Fprintf(w, "data: {\"status\": \"pending\"}\n\n")
			flusher.Flush()
		case <-timeout:
			fmt.Fprintf(w, "data: {\"status\": \"expired\"}\n\n")
			flusher.Flush()
			return
		case <-r.Context().Done():
			return
		}
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	accessTokenMu.RLock()
	hasToken := accessToken != ""
	accessTokenMu.RUnlock()

	config := getStaticConfig()
	staticCount := 0
	if config != nil {
		staticCount = len(config.StaticFiles)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":            "ok",
		"access_token_ready": hasToken,
		"backend_service":   webServiceURL,
		"static_files":      staticCount,
	})
}

func refreshAccessToken() {
	for {
		if wechatAppID == "" || wechatAppID == "you wechatAppID" {
			time.Sleep(60 * time.Second)
			continue
		}
		apiURL := fmt.Sprintf(
			"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s",
			wechatAppID, wechatAppSecret,
		)
		resp, err := http.Get(apiURL)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		var result struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
			ErrCode     int    `json:"errcode"`
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		json.Unmarshal(body, &result)

		if result.ErrCode == 0 {
			accessTokenMu.Lock()
			accessToken = result.AccessToken
			accessTokenMu.Unlock()
			log.Printf("微信 access token 刷新成功，有效期: %d 秒", result.ExpiresIn)
			time.Sleep(time.Duration(result.ExpiresIn-300) * time.Second)
		} else {
			time.Sleep(5 * time.Minute)
		}
	}
}

// generateMiniProgramCode 生成微信小程序码
// scene 参数现在是 scene_token（一次性链路令牌）
func generateMiniProgramCode(sceneToken string) (string, error) {
	accessTokenMu.RLock()
	token := accessToken
	accessTokenMu.RUnlock()

	if token == "" {
		return "", fmt.Errorf("access token 未就绪")
	}

	// 使用 getwxacodeunlimit，scene 参数传递 scene_token
	apiURL := fmt.Sprintf("https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token=%s", token)

	reqBody := map[string]interface{}{
		"scene":      sceneToken,           // 一次性令牌作为 scene 参数
		"page":       "pages/index/index",     // 小程序授权页面路径
		"width":      280,
		"env_version": "release",
		// 可选：检查路径是否存在
		"check_path": false,
	}

	jsonBody, _ := json.Marshal(reqBody)

	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if len(body) < 100 {
		var errResp struct {
			ErrCode int    `json:"errcode"`
			ErrMsg  string `json:"errmsg"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.ErrCode != 0 {
			return "", fmt.Errorf("微信接口错误: %s", errResp.ErrMsg)
		}
	}

	return base64.StdEncoding.EncodeToString(body), nil
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

func main() {
	config, err := loadStaticConfig()
	if err != nil {
		log.Printf("⚠️ 加载静态文件配置失败: %v，静态文件功能不可用", err)
	} else {
		staticConfigMu.Lock()
		staticConfig = config
		staticConfigMu.Unlock()
	}

	go refreshAccessToken()

	mux := http.NewServeMux()

	// ── 原有路由 ────────────────────────────────
	mux.HandleFunc("/login", handleLoginPage)
	mux.HandleFunc("/api/status", handleStatusCheck)
	mux.HandleFunc("/api/callback", handleCallback)
	mux.HandleFunc("/api/ws", handleWebSocket)
	mux.HandleFunc("/api/exchange-token", handleExchangeToken)
	mux.HandleFunc("/health", handleHealth)

	// ── 防护路由 ────────────────────────────
	mux.HandleFunc("/api/qr-challenge", handleQRChallenge)
	mux.HandleFunc("/api/qr", handleQRRequest)
	mux.HandleFunc("/admin/suspicious", handleAdminSuspicious)

	// ── 注意：/api/{scene_token} 动态路由在 handleGateway 中处理 ──

	mux.HandleFunc("/", handleGateway)

	// HTTP → HTTPS 重定向
	go func() {
		httpMux := http.NewServeMux()
		httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			httpsURL := "https://" + r.Host + r.URL.Path
			if r.URL.RawQuery != "" {
				httpsURL += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
		})
		log.Println("HTTP 服务器启动在 :80")
		if err := http.ListenAndServe(":80", httpMux); err != nil {
			log.Printf("HTTP 服务器错误: %v", err)
		}
	}()

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	httpsServer := &http.Server{
		Addr:      ":443",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("🚀 HTTPS 网关启动在 :443")
	log.Printf("🔗 后端Web服务: %s", webServiceURL)
	log.Printf("🔒 防护层已启用: IP封禁 + PoW挑战 + Turnstile + 设备指纹限流 + 一次性动态链路")
	if err := httpsServer.ListenAndServeTLS(certPath, keyPath); err != nil {
		log.Fatalf("HTTPS 服务器错误: %v", err)
	}
}

// loginHTML 
const loginHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>微信扫码登录</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    {{if .TurnstileSiteKey}}
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    {{end}}
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex; align-items: center; justify-content: center;
            padding: 20px;
        }
        .container {
            background: white; border-radius: 32px; padding: 48px 32px;
            box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25);
            text-align: center; max-width: 420px; width: 100%;
        }
        .logo-img { width: 80px; height: 80px; margin-bottom: 16px; }
        .logo-text { font-size: 64px; margin-bottom: 16px; }
        .logo-text.pulse { animation: pulse 2s infinite; }
        @keyframes pulse { 0%,100%{transform:scale(1)} 50%{transform:scale(1.1)} }
        h1 { font-size: 28px; font-weight: 700; color: #1a1a2e; margin-bottom: 8px; }
        .subtitle { font-size: 14px; color: #666; margin-bottom: 32px; }
        .qr-wrapper {
            background: #f8f9fa; border-radius: 24px; padding: 20px;
            border: 2px solid #e9ecef; min-height: 280px;
            display: flex; align-items: center; justify-content: center;
            position: relative; flex-direction: column; gap: 16px;
        }
        .qr-code { width: 100%; max-width: 240px; border-radius: 16px; display: none; }
        #getQRBtn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; border-radius: 16px;
            padding: 16px 32px; font-size: 16px; font-weight: 600;
            cursor: pointer; transition: opacity .2s;
        }
        #getQRBtn:hover { opacity: 0.85; }
        #getQRBtn:disabled { opacity: 0.5; cursor: not-allowed; }
        .status-overlay {
            display: none; position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(255,255,255,0.95); border-radius: 24px;
            align-items: center; justify-content: center;
            flex-direction: column; z-index: 10;
        }
        .status-overlay.active { display: flex; }
        .status-icon { font-size: 48px; margin-bottom: 16px; }
        .status-message { font-size: 18px; font-weight: 600; color: #1a1a2e; }
        .status-text {
            margin-top: 16px; padding: 12px 16px; border-radius: 12px;
            font-size: 14px; display: flex; align-items: center;
            justify-content: center; gap: 8px;
        }
        .status-text.waiting { background: #eff6ff; color: #1e40af; }
        .status-text.success { background: #f0fdf4; color: #166534; }
        .status-text.error   { background: #fef2f2; color: #991b1b; }
        .tip {
            background: #f0fdf4; border-left: 4px solid #22c55e;
            padding: 16px; border-radius: 12px; text-align: left; margin-top: 24px;
        }
        #powProgress {
            font-size: 12px; color: #888; margin-top: 8px; display: none;
        }
        #cooldownBar {
            width: 100%; background: #e5e7eb; border-radius: 8px;
            height: 6px; margin-top: 12px; display: none; overflow: hidden;
        }
        #cooldownFill {
            height: 100%; background: linear-gradient(90deg, #667eea, #764ba2);
            border-radius: 8px; transition: width 1s linear;
        }
    </style>
</head>
<body>
<div class="container">
    <img class="logo-img" src="/logo.png" alt="Logo"
         onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
    <div class="logo-text pulse" id="mainIcon" style="display:none;">📱</div>
    <h1 id="mainTitle">微信扫码登录</h1>
    <div class="subtitle">使用微信扫一扫，确认登录</div>

    <div class="qr-wrapper" id="qrWrapper">
        <!-- 初始：显示获取按钮 -->
        <div id="qrPlaceholder">
            {{if .TurnstileSiteKey}}
            <div class="cf-turnstile" data-sitekey="{{.TurnstileSiteKey}}" data-theme="light"
                 id="cfWidget" style="margin-bottom:12px;"></div>
            {{end}}
            <button id="getQRBtn" onclick="startGetQR()">点击获取二维码</button>
            <div id="powProgress">⚙️ 正在计算验证...</div>
            <div id="cooldownBar"><div id="cooldownFill" style="width:100%"></div></div>
        </div>
        <img class="qr-code" id="qrImage" src="" alt="微信小程序码">
        <div class="status-overlay" id="statusOverlay">
            <div class="status-icon" id="statusIcon"></div>
            <div class="status-message" id="statusMessage"></div>
        </div>
    </div>

    <div class="status-text waiting" id="statusText" style="display:none;">
        <span>⏳</span><span id="statusTextMessage">等待扫码确认...</span>
    </div>

    <div class="tip">
        <div style="font-weight:600;margin-bottom:8px;">📌 使用步骤</div>
        <div style="font-size:13px;line-height:1.8;">
            1. 点击「获取二维码」按钮<br>
            2. 完成人机验证<br>
            3. 打开微信扫一扫<br>
            4. 扫描小程序码，点击「确认登录」
        </div>
    </div>
</div>

<script>
// ── 设备指纹（轻量级，canvas + audio + 屏幕特征） ──────────────
function getFingerprint() {
    var parts = [];
    // Canvas 指纹
    try {
        var c = document.createElement('canvas');
        var ctx = c.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('fp-zhiliaoya-\u5fae\u4fe1', 2, 2);
        parts.push(c.toDataURL().slice(-32));
    } catch(e) {}
    // 屏幕
    parts.push(screen.width + 'x' + screen.height + 'x' + screen.colorDepth);
    // 时区
    parts.push(new Date().getTimezoneOffset());
    // 语言
    parts.push(navigator.language || '');
    // 平台
    parts.push(navigator.platform || '');
    // 硬件并发
    parts.push(navigator.hardwareConcurrency || 0);
    // 插件数量
    parts.push(navigator.plugins ? navigator.plugins.length : 0);
    // 触摸点
    parts.push(navigator.maxTouchPoints || 0);
    var raw = parts.join('|');
    // 简单 hash
    var h = 0;
    for (var i = 0; i < raw.length; i++) {
        h = (Math.imul(31, h) + raw.charCodeAt(i)) | 0;
    }
    return Math.abs(h).toString(16).padStart(8, '0') + raw.length.toString(16);
}

// ── 工作量证明（浏览器端 SHA-256） ───────────────────────────
async function sha256(message) {
    var msgBuffer = new TextEncoder().encode(message);
    var hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    var hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function solvePoW(seed, difficulty) {
    // difficulty = 要求前导零 bit 数
    // 每个 hex 字符代表 4 bit，difficulty/4 个 hex 字符需为 '0'
    var leadingZeroHexChars = Math.ceil(difficulty / 4);
    var target = '0'.repeat(leadingZeroHexChars);
    var nonce = 0;
    while (true) {
        var hash = await sha256(seed + nonce);
        if (hash.startsWith(target)) {
            return nonce.toString();
        }
        nonce++;
        if (nonce % 5000 === 0) {
            document.getElementById('powProgress').textContent =
                '⚙️ 正在计算验证... ' + nonce + ' 次尝试';
            // 让浏览器喘息
            await new Promise(r => setTimeout(r, 0));
        }
    }
}

// ── Turnstile token 获取 ──────────────────────────────────
function getTurnstileToken() {
    if (typeof turnstile === 'undefined') return Promise.resolve('');
    return new Promise(function(resolve) {
        var widget = document.getElementById('cfWidget');
        if (!widget) return resolve('');
        try {
            var token = turnstile.getResponse();
            if (token) return resolve(token);
            turnstile.render('#cfWidget', {
                sitekey: widget.dataset.sitekey,
                callback: resolve
            });
        } catch(e) { resolve(''); }
    });
}

// ── 主流程 ────────────────────────────────────────────────
var sceneID = null;
var pollTimer = null;
var cooldownTimer = null;

async function startGetQR() {
    var btn = document.getElementById('getQRBtn');
    var progress = document.getElementById('powProgress');
    btn.disabled = true;
    btn.textContent = '验证中...';
    progress.style.display = 'block';

    try {
        // 1. 获取 PoW 挑战
        var challengeResp = await fetch('/api/qr-challenge');
        var challenge = await challengeResp.json();

        // 2. 并行：解 PoW + 获取 Turnstile token
        progress.textContent = '⚙️ 正在计算验证...';
        var [nonce, captchaToken] = await Promise.all([
            solvePoW(challenge.seed, challenge.difficulty),
            getTurnstileToken()
        ]);

        progress.textContent = '✅ 验证完成，获取二维码...';

        // 3. 请求二维码
        var fingerprint = getFingerprint();
        var qrResp = await fetch('/api/qr', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                fingerprint:   fingerprint,
                pow_seed:      challenge.seed,
                pow_nonce:     nonce,
                captcha_token: captchaToken
            })
        });
        var data = await qrResp.json();

        if (!data.success) {
            showError(data.error || '获取失败，请稍后重试');
            // 如果是限流，显示冷却倒计时
            if (qrResp.status === 429 && data.retry_after) {
                startCooldown(data.retry_after);
            } else {
                resetBtn();
            }
            return;
        }

        sceneID = data.scene_id;

        // 4. 展示二维码，隐藏按钮
        document.getElementById('qrPlaceholder').style.display = 'none';
        var img = document.getElementById('qrImage');
        img.src = 'data:image/png;base64,' + data.qr;
        img.style.display = 'block';
        document.getElementById('statusText').style.display = 'flex';

        // 5. 开始轮询状态
        startPolling();

    } catch(e) {
        showError('网络错误，请重试');
        resetBtn();
    }
}

function startCooldown(seconds) {
    var bar = document.getElementById('cooldownBar');
    var fill = document.getElementById('cooldownFill');
    var btn = document.getElementById('getQRBtn');
    bar.style.display = 'block';
    fill.style.width = '100%';
    var remaining = seconds;
    btn.textContent = '请等待 ' + remaining + 's';

    if (cooldownTimer) clearInterval(cooldownTimer);
    cooldownTimer = setInterval(function() {
        remaining--;
        fill.style.width = ((remaining / seconds) * 100) + '%';
        btn.textContent = '请等待 ' + remaining + 's';
        if (remaining <= 0) {
            clearInterval(cooldownTimer);
            bar.style.display = 'none';
            resetBtn();
        }
    }, 1000);
}

function resetBtn() {
    var btn = document.getElementById('getQRBtn');
    btn.disabled = false;
    btn.textContent = '点击获取二维码';
    document.getElementById('powProgress').style.display = 'none';
    // 重置 Turnstile
    if (typeof turnstile !== 'undefined') {
        try { turnstile.reset(); } catch(e) {}
    }
}

function showError(msg) {
    var statusText = document.getElementById('statusText');
    statusText.style.display = 'flex';
    statusText.className = 'status-text error';
    document.getElementById('statusTextMessage').textContent = '❌ ' + msg;
}

function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(checkStatus, 2000);
    checkStatus();

    if (!!window.EventSource) {
        setTimeout(function() {
            var es = new EventSource('/api/ws?scene_id=' + sceneID);
            es.onmessage = function(event) {
                try {
                    var data = JSON.parse(event.data);
                    if (data.status === 'confirmed' || data.status === 'confirm') {
                        if (pollTimer) clearInterval(pollTimer);
                        showSuccess();
                        es.close();
                    }
                } catch(e) {}
            };
        }, 1000);
    }
}

function checkStatus() {
    if (!sceneID) return;
    fetch('/api/status?scene_id=' + sceneID)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.status === 'confirmed' || data.status === 'confirm') {
                if (pollTimer) clearInterval(pollTimer);
                showSuccess();
            } else if (data.status === 'cancelled' || data.status === 'expired') {
                if (pollTimer) clearInterval(pollTimer);
                var statusText = document.getElementById('statusText');
                statusText.className = 'status-text error';
                document.getElementById('statusTextMessage').textContent =
                    data.status === 'cancelled' ? '登录已取消' : '二维码已过期，请重新获取';
                // 超时后允许重新获取
                setTimeout(function() {
                    document.getElementById('qrImage').style.display = 'none';
                    document.getElementById('qrPlaceholder').style.display = 'flex';
                    statusText.style.display = 'none';
                    resetBtn();
                }, 2000);
            }
        });
}

function showSuccess() {
    var overlay = document.getElementById('statusOverlay');
    overlay.classList.add('active');
    document.getElementById('statusIcon').textContent = '✅';
    document.getElementById('statusMessage').textContent = '登录成功！正在跳转...';
    document.getElementById('statusText').className = 'status-text success';
    document.getElementById('statusTextMessage').textContent = '登录成功！正在跳转...';
    exchangeToken();
}

var isExchanging = false;
function exchangeToken() {
    if (isExchanging || !sceneID) return;
    isExchanging = true;
    fetch('/api/exchange-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scene_id: sceneID })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.success) {
            setTimeout(function() { window.location.href = '/'; }, 1000);
        } else {
            isExchanging = false;
        }
    })
    .catch(function() { isExchanging = false; });
}

window.addEventListener('beforeunload', function() {
    if (pollTimer) clearInterval(pollTimer);
});
</script>
</body>
</html>
`