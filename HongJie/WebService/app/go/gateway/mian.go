package main

import (
	"bytes"
	"crypto/rand"
	"crypto/hmac"
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

	jwtSecret = func() []byte {
		if s := os.Getenv("JWT_SECRET"); s != "" {
			return []byte(s)
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			panic("JWT_SECRET 未设置且随机生成失败")
		}
		log.Printf("⚠️ JWT_SECRET 未设置，使用随机密钥（服务重启后所有用户将需重新登录）")
		return b
	}()

	accessToken   string
	accessTokenMu sync.RWMutex

	sceneStore       = NewSceneStore()
	authSessionStore = NewAuthSessionStore()

	staticConfig   *StaticConfig
	staticConfigMu sync.RWMutex

	qrRateLimiter  = NewQRRateLimiter()
	ipBanList      = NewIPBanList()
	suspiciousLog  = NewSuspiciousLogger()
	challengeStore = NewChallengeStore()
)

// ─────────────────────────────────────────────
// 场景令牌存储（一次性动态链路）
// ─────────────────────────────────────────────

type SceneToken struct {
	Token     string    `json:"token"`
	SceneID   string    `json:"scene_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

type SceneTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*SceneToken
	scenes map[string]string
}

func NewSceneTokenStore() *SceneTokenStore {
	s := &SceneTokenStore{
		tokens: make(map[string]*SceneToken),
		scenes: make(map[string]string),
	}
	go s.cleanup()
	return s
}

func (s *SceneTokenStore) CreateToken(sceneID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

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

	st.Used = true
	return st.SceneID, true
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
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ─────────────────────────────────────────────
// 授权会话存储（绑定客户端与 scene_id）
// ─────────────────────────────────────────────

type AuthSession struct {
	SessionID string    `json:"session_id"`
	SceneID   string    `json:"scene_id"`
	Exchanged bool      `json:"exchanged"`
	CreatedAt time.Time `json:"created_at"`
}

type AuthSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*AuthSession
}

func NewAuthSessionStore() *AuthSessionStore {
	s := &AuthSessionStore{
		sessions: make(map[string]*AuthSession),
	}
	go s.cleanup()
	return s
}

func (s *AuthSessionStore) Create(sceneID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessionID := generateAuthSessionID()
	s.sessions[sessionID] = &AuthSession{
		SessionID: sessionID,
		SceneID:   sceneID,
		CreatedAt: time.Now(),
	}
	return sessionID
}

func (s *AuthSessionStore) Get(sessionID string) (*AuthSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	as, ok := s.sessions[sessionID]
	return as, ok
}

func (s *AuthSessionStore) MarkExchanged(sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	as, ok := s.sessions[sessionID]
	if !ok || as.Exchanged {
		return false
	}
	as.Exchanged = true
	return true
}

func (s *AuthSessionStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, as := range s.sessions {
			if now.Sub(as.CreatedAt) > 10*time.Minute {
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

func generateAuthSessionID() string {
	b := make([]byte, 32)
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
	SceneID   string    `json:"scene_id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	UserID    string    `json:"user_id,omitempty"`
	OpenID    string    `json:"-"` // 仅内部记录，绝不输出
}

type SceneStore struct {
	mu     sync.RWMutex
	scenes map[string]*SceneStatus
}

// ─────────────────────────────────────────────
// JWT 授权令牌（HS256）
// ─────────────────────────────────────────────

// JWTClaims 是 JWT payload 的结构
type JWTClaims struct {
	UserID  string `json:"uid"`
	SceneID string `json:"sid"`
	Iat     int64  `json:"iat"` // issued at
	Exp     int64  `json:"exp"` // expires at
}

func jwtBase64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// issueJWT 生成一个有效期 24h 的 JWT
func issueJWT(userID, sceneID string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(24 * time.Hour)
	claims := JWTClaims{
		UserID:  userID,
		SceneID: sceneID,
		Iat:     now.Unix(),
		Exp:     exp.Unix(),
	}
	header := jwtBase64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	payload := jwtBase64(payloadBytes)
	signing := header + "." + payload
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(signing))
	sig := jwtBase64(mac.Sum(nil))
	token := signing + "." + sig
	log.Printf("✅ 生成 JWT [UserID: %s, 过期: %s]", userID, exp.Format(time.RFC3339))
	return token, exp, nil
}

// validateJWT 验证签名并返回 claims，不查内存表
func validateJWT(token string) (*JWTClaims, bool) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, false
	}
	signing := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(signing))
	expectedSig := jwtBase64(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims JWTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, false
	}
	if time.Now().Unix() > claims.Exp {
		return nil, false
	}
	return &claims, true
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
		scene.OpenID = openID // 内部记录，JSON不输出
	}
	log.Printf("🔄 场景状态变更 [SceneID: %s, %s -> %s, UserID: %s]",
		sceneID, oldStatus, status, scene.UserID)
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
			if now.Sub(scene.CreatedAt) > 5*time.Minute {
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

func generateUserID() string {
	b := make([]byte, 16)
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
// API：生成二维码（返回动态链路，通过 cookie 绑定会话）
// ─────────────────────────────────────────────

func handleQRRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := getClientIP(r)
	w.Header().Set("Content-Type", "application/json")

	if ipBanList.IsBanned(ip) {
		suspiciousLog.Log(ip, "banned_ip_qr", "封禁期间请求二维码")
		ipBanList.AddStrike(ip)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "error": "请求被拒绝，请稍后再试",
		})
		return
	}

	var req struct {
		Fingerprint string `json:"fingerprint"`
		PowSeed     string `json:"pow_seed"`
		PowNonce    string `json:"pow_nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

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

	if !challengeStore.Verify(req.PowSeed, req.PowNonce) {
		suspiciousLog.Log(ip, "pow_failed", fmt.Sprintf("seed=%s", req.PowSeed))
		ipBanList.AddStrike(ip)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "error": "工作量证明验证失败，请刷新重试",
		})
		return
	}

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

	sceneID := generateSceneID()
	sceneStore.CreateScene(sceneID)

	sceneToken := sceneTokenStore.CreateToken(sceneID)

	qrBase64, err := generateMiniProgramCode(sceneToken)
	if err != nil {
		log.Printf("❌ 生成二维码失败: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "error": "生成二维码失败，请稍后重试",
		})
		return
	}

	sessionID := authSessionStore.Create(sceneID)

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_session",
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	log.Printf("✅ 二维码生成成功 [IP: %s, SceneID: %s, SessionID: %s]", ip, sceneID, sessionID[:16])

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"qr":      qrBase64,
	})
}

// ─────────────────────────────────────────────
// 动态链路处理（微信小程序回调）
// ─────────────────────────────────────────────

func handleSceneTokenCallback(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/")
	if len(path) != 32 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "无效的链接",
		})
		return
	}

	sceneToken := path

	sceneID, valid := sceneTokenStore.Validate(sceneToken)
	if !valid {
		log.Printf("❌ 无效或已使用的一次性链路 [Token: %s]", sceneToken[:16])
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "链接已失效或已被使用",
		})
		return
	}

	_, exists := sceneStore.GetScene(sceneID)
	if !exists {
		log.Printf("❌ 场景不存在 [SceneID: %s]", sceneID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "场景已过期",
		})
		return
	}

	var body struct {
		Action string `json:"action"`
		Code   string `json:"code"`
	}
	if r.Method == "POST" {
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
	}

	// 小程序取消登录：action=cancel，无 code
	if body.Action == "cancel" {
		sceneStore.UpdateScene(sceneID, "cancelled", "", "")
		log.Printf("🚫 用户取消登录 [SceneID: %s]", sceneID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true, "message": "已取消登录",
		})
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		code = body.Code
	}

	if code == "" {
		log.Printf("⚠️ 缺少微信 code [SceneID: %s]", sceneID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "缺少微信授权码",
		})
		return
	}

	openID, err := getWechatOpenID(code)
	if err != nil {
		log.Printf("❌ 获取 OpenID 失败 [SceneID: %s, Code: %s, Error: %v]", sceneID, code[:10], err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "微信验证失败，请重新扫码",
		})
		return
	}

	userID := generateUserID()
	updatedScene, _ := sceneStore.UpdateScene(sceneID, "confirmed", userID, openID)

	log.Printf("✅ 微信验证成功 [SceneID: %s, UserID: %s]", sceneID, userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "登录确认成功",
		"status":  updatedScene.Status,
	})
}

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
	// RFC-1918 + loopback
	for _, prefix := range []string{"127.", "10.", "192.168.", "::1"} {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	// 172.16.0.0/12 覆盖 172.16.x.x ～ 172.31.x.x（含 Docker 默认 bridge 网段）
	if strings.HasPrefix(ip, "172.") {
		parts := strings.SplitN(ip, ".", 3)
		if len(parts) >= 2 {
			second, err := strconv.Atoi(parts[1])
			if err == nil && second >= 16 && second <= 31 {
				return true
			}
		}
	}
	return false
}

// ─────────────────────────────────────────────
// 网关主入口
// ─────────────────────────────────────────────

func handleGateway(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") && len(r.URL.Path) == 37 {
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
		if claims, valid := validateJWT(authCookie.Value); valid {
			log.Printf("✅ 已认证 [UserID: %s]，代理转发", claims.UserID)
			proxyToBackend(w, r, claims)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:   "auth_token",
			Value:  "",
			Path:   "/",
			MaxAge: -1, HttpOnly: true, Secure: true,
		})
	}

	log.Printf("👤 未认证，跳转登录页")
	http.Redirect(w, r, "/login", http.StatusFound)
}

func proxyToBackend(w http.ResponseWriter, r *http.Request, claims *JWTClaims) {
	target, err := url.Parse(webServiceURL)
	if err != nil {
		http.Error(w, "服务不可用", http.StatusServiceUnavailable)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Set("X-User-ID", claims.UserID)
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
		if claims, valid := validateJWT(authCookie.Value); valid {
			proxyToBackend(w, r, claims)
			return
		}
	}

	tmpl := template.Must(template.New("login").Parse(loginHTML))
	tmpl.Execute(w, nil)
}

// ─────────────────────────────────────────────
// 令牌交换（通过 auth_session cookie 获取）
// ─────────────────────────────────────────────

func handleExchangeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionCookie, err := r.Cookie("auth_session")
	if err != nil || sessionCookie.Value == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "会话无效或已过期",
		})
		return
	}

	sessionID := sessionCookie.Value
	session, ok := authSessionStore.Get(sessionID)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "会话不存在",
		})
		return
	}

	scene, exists := sceneStore.GetScene(session.SceneID)
	if !exists || scene.Status != "confirmed" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "场景未确认或已过期",
		})
		return
	}

	if !authSessionStore.MarkExchanged(sessionID) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "授权已兑换，请刷新重试",
		})
		return
	}

	jwtToken, jwtExp, err := issueJWT(scene.UserID, session.SceneID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false, "message": "生成令牌失败，请重试",
		})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    jwtToken,
		Path:     "/",
		Expires:  jwtExp,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:   "auth_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1, HttpOnly: true, Secure: true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "授权成功，正在跳转...",
	})
}

// ─────────────────────────────────────────────
// 状态查询（通过 auth_session cookie 获取）
// ─────────────────────────────────────────────

func handleStatusCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sessionCookie, err := r.Cookie("auth_session")
	if err != nil || sessionCookie.Value == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "expired",
			"message": "会话不存在",
		})
		return
	}

	sessionID := sessionCookie.Value
	session, ok := authSessionStore.Get(sessionID)
	if !ok {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "expired",
			"message": "会话已过期",
		})
		return
	}

	scene, exists := sceneStore.GetScene(session.SceneID)
	if !exists {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "expired",
			"message": "场景已过期",
		})
		return
	}

	resp := map[string]interface{}{
		"status":    scene.Status,
		"user_id":   scene.UserID,
		"timestamp": scene.UpdatedAt.Unix(),
	}
	if scene.Status == "confirmed" {
		resp["need_exchange"] = true
	}
	json.NewEncoder(w).Encode(resp)
}

// ─────────────────────────────────────────────
// WebSocket / SSE 状态推送（通过 auth_session cookie）
// ─────────────────────────────────────────────

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	sessionCookie, err := r.Cookie("auth_session")
	if err != nil || sessionCookie.Value == "" {
		http.Error(w, "会话无效", http.StatusUnauthorized)
		return
	}
	sessionID := sessionCookie.Value
	session, ok := authSessionStore.Get(sessionID)
	if !ok {
		http.Error(w, "会话不存在", http.StatusUnauthorized)
		return
	}
	sceneID := session.SceneID

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	fmt.Fprintf(w, "data: {\"status\": \"connected\"}\n\n")
	flusher.Flush()

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
		"status":             "ok",
		"access_token_ready": hasToken,
		"backend_service":    webServiceURL,
		"static_files":       staticCount,
	})
}

func refreshAccessToken() {
	for {
		if wechatAppID == "" || wechatAppSecret == "" {
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

func generateMiniProgramCode(sceneToken string) (string, error) {
	accessTokenMu.RLock()
	token := accessToken
	accessTokenMu.RUnlock()

	if token == "" {
		return "", fmt.Errorf("access token 未就绪")
	}

	apiURL := fmt.Sprintf("https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token=%s", token)

	reqBody := map[string]interface{}{
		"scene":      sceneToken,
		"page":       "pages/index/index",
		"width":      280,
		"env_version": "release",
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

// HTML
const loginHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>微信扫码登录</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: #161b22;
            border: 1px solid #21262d;
            border-radius: 12px;
            padding: 48px 32px;
            text-align: center;
            max-width: 420px;
            width: 100%;
            margin: auto;
        }
        .avatar {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            flex-shrink: 0;
            margin-bottom: 16px; /* 保持原间距 */
        }
        @keyframes pulse { 0%,100%{transform:scale(1)} 50%{transform:scale(1.1)} }
        h1 {
            font-size: 28px;
            font-weight: 700;
            color: #f0f6fc;
            margin-bottom: 8px;
        }
        .subtitle {
            font-size: 14px;
            color: #8b949e;
            margin-bottom: 32px;
        }
        .qr-wrapper {
            background: #0d1117;
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #21262d;
            min-height: 280px;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            flex-direction: column;
            gap: 16px;
        }
        .qr-code {
            width: 100%;
            max-width: 240px;
            border-radius: 12px;
            display: none;
        }
        #getQRBtn {
            background: #238636;
            color: white;
            border: 1px solid #2ea043;
            border-radius: 8px;
            padding: 12px 24px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        #getQRBtn:hover { background: #2ea043; }
        #getQRBtn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .status-overlay {
            display: none;
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(22,27,34,0.95);
            border-radius: 12px;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            z-index: 10;
        }
        .status-overlay.active { display: flex; }
        .status-icon { font-size: 48px; margin-bottom: 16px; }
        .status-message {
            font-size: 18px;
            font-weight: 600;
            color: #f0f6fc;
        }
        .status-text {
            margin-top: 16px;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        .status-text.waiting { background: #1a2332; color: #58a6ff; }
        .status-text.success { background: #0d2a1e; color: #3fb950; }
        .status-text.error   { background: #2a1215; color: #f85149; }
        .tip {
            background: #0d2a1e;
            border-left: 4px solid #3fb950;
            padding: 16px;
            border-radius: 8px;
            text-align: left;
            margin-top: 24px;
            color: #c9d1d9;
        }
        #powProgress {
            font-size: 12px;
            color: #8b949e;
            margin-top: 8px;
            display: none;
        }
        #cooldownBar {
            width: 100%;
            background: #21262d;
            border-radius: 8px;
            height: 6px;
            margin-top: 12px;
            display: none;
            overflow: hidden;
        }
        #cooldownFill {
            height: 100%;
            background: #238636;
            border-radius: 8px;
            transition: width 1s linear;
        }
        /* 底部备案 */
        .footer {
            text-align: center;
            padding: 20px;
            font-size: 12px;
            color: #484f58;
            width: 100%;
            margin-top: auto;
        }
        .footer a {
            color: #484f58;
            text-decoration: none;
            margin: 0 8px;
        }
        .footer a:hover {
            color: #58a6ff;
            text-decoration: underline;
        }
    </style>
</head>
<body>
<div class="container">
    <img class="avatar" src="https://zhiliaoya.cn/logo.png" alt="知了涯">
    <h1 id="mainTitle">微信扫码登录</h1>
    <div class="subtitle">使用微信扫一扫，确认登录</div>

    <div class="qr-wrapper" id="qrWrapper">
        <div id="qrPlaceholder">
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
            2. 打开微信扫一扫<br>
            3. 扫描小程序码，点击「确认登录」
        </div>
    </div>
</div>

<!-- 底部备案 -->
<div class="footer">
    <p>
        <a href="https://beian.miit.gov.cn/" target="_blank">黔ICP备2026047859号</a>
        <a href="https://beian.mps.gov.cn/#/query/webSearch?code=52040002000182" target="_blank">贵公网安备52040002000182号</a>
    </p>
    <p style="margin-top:0.5rem;">© 2026 知了涯 zhiliaoya.cn</p>
</div>

<script>
function getFingerprint() {
    var parts = [];
    try {
        var c = document.createElement('canvas');
        var ctx = c.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('fp-zhiliaoya-\u5fae\u4fe1', 2, 2);
        parts.push(c.toDataURL().slice(-32));
    } catch(e) {}
    parts.push(screen.width + 'x' + screen.height + 'x' + screen.colorDepth);
    parts.push(new Date().getTimezoneOffset());
    parts.push(navigator.language || '');
    parts.push(navigator.platform || '');
    parts.push(navigator.hardwareConcurrency || 0);
    parts.push(navigator.plugins ? navigator.plugins.length : 0);
    parts.push(navigator.maxTouchPoints || 0);
    var raw = parts.join('|');
    var h = 0;
    for (var i = 0; i < raw.length; i++) {
        h = (Math.imul(31, h) + raw.charCodeAt(i)) | 0;
    }
    return Math.abs(h).toString(16).padStart(8, '0') + raw.length.toString(16);
}

async function sha256(message) {
    var msgBuffer = new TextEncoder().encode(message);
    var hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    var hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function solvePoW(seed, difficulty) {
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
            await new Promise(r => setTimeout(r, 0));
        }
    }
}

var pollTimer = null;
var cooldownTimer = null;

async function startGetQR() {
    var btn = document.getElementById('getQRBtn');
    var progress = document.getElementById('powProgress');
    btn.disabled = true;
    btn.textContent = '验证中...';
    progress.style.display = 'block';

    try {
        var challengeResp = await fetch('/api/qr-challenge');
        var challenge = await challengeResp.json();

        progress.textContent = '⚙️ 正在计算验证...';
        var nonce = await solvePoW(challenge.seed, challenge.difficulty);

        progress.textContent = '✅ 验证完成，获取二维码...';

        var fingerprint = getFingerprint();
        var qrResp = await fetch('/api/qr', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                fingerprint: fingerprint,
                pow_seed:    challenge.seed,
                pow_nonce:   nonce
            })
        });
        var data = await qrResp.json();

        if (!data.success) {
            showError(data.error || '获取失败，请稍后重试');
            if (qrResp.status === 429 && data.retry_after) {
                startCooldown(data.retry_after);
            } else {
                resetBtn();
            }
            return;
        }

        document.getElementById('qrPlaceholder').style.display = 'none';
        var img = document.getElementById('qrImage');
        img.src = 'data:image/png;base64,' + data.qr;
        img.style.display = 'block';
        document.getElementById('statusText').style.display = 'flex';

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
            var es = new EventSource('/api/ws');
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
    fetch('/api/status')
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
    if (isExchanging) return;
    isExchanging = true;
    fetch('/api/exchange-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
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

	mux.HandleFunc("/login", handleLoginPage)
	mux.HandleFunc("/api/status", handleStatusCheck)
	mux.HandleFunc("/api/ws", handleWebSocket)
	mux.HandleFunc("/api/exchange-token", handleExchangeToken)
	mux.HandleFunc("/health", handleHealth)

	mux.HandleFunc("/api/qr-challenge", handleQRChallenge)
	mux.HandleFunc("/api/qr", handleQRRequest)
	mux.HandleFunc("/admin/suspicious", handleAdminSuspicious)

	mux.HandleFunc("/", handleGateway)

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
	log.Printf("🔒 防护层已启用: IP封禁 + PoW挑战 + 设备指纹限流 + 一次性动态链路 + 零OpenID暴露")
	if err := httpsServer.ListenAndServeTLS(certPath, keyPath); err != nil {
		log.Fatalf("HTTPS 服务器错误: %v", err)
	}
}
