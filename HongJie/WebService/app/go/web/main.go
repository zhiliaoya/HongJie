// app/go/web/main.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var startTime = time.Now()

func main() {
	mux := http.NewServeMux()

	// 页面路由
	mux.HandleFunc("/", handleIndex)        // 首页
	mux.HandleFunc("/health", handleHealth) // 健康检查
	mux.HandleFunc("/api/info", handleAPIInfo)
	mux.HandleFunc("/api/time", handleAPITime)

	server := &http.Server{
		Addr:         ":80",
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("正在关闭 Web 服务...")
		if err := server.Close(); err != nil {
			log.Printf("关闭错误: %v", err)
		}
	}()

	log.Println("Web 服务启动在 :80")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("服务启动失败: %v", err)
	}
	log.Println("Web 服务已停止")
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CoolGate - 零数据认证网关</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            min-height: 100vh;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 3rem 1.5rem;
        }

        /* 头部 */
        .header {
            text-align: center;
            margin-bottom: 3rem;
        }

        .logo {
            font-size: 4rem;
            margin-bottom: 1rem;
        }

        h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #fff, #e0d4ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .tagline {
            font-size: 1.2rem;
            opacity: 0.9;
            margin-bottom: 1rem;
        }

        .badge {
            display: inline-flex;
            gap: 0.5rem;
            margin-top: 1rem;
        }

        .badge a {
            color: #fff;
            text-decoration: none;
            background: rgba(255,255,255,0.2);
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            transition: background 0.2s;
        }

        .badge a:hover {
            background: rgba(255,255,255,0.3);
        }

        /* 特性卡片 */
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }

        .feature-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 1.5rem;
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.2s, border-color 0.2s;
        }

        .feature-card:hover {
            transform: translateY(-4px);
            border-color: rgba(255,255,255,0.4);
        }

        .feature-icon {
            font-size: 2rem;
            margin-bottom: 1rem;
        }

        .feature-title {
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .feature-desc {
            font-size: 0.85rem;
            opacity: 0.8;
            line-height: 1.5;
        }

        /* 代码块 */
        .code-block {
            background: #1a1a2e;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            overflow-x: auto;
        }

        .code-block pre {
            color: #00ff9d;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            margin: 0;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1rem;
            text-align: center;
        }

        .section-subtitle {
            text-align: center;
            opacity: 0.8;
            margin-bottom: 2rem;
        }

        /* 快速开始 */
        .quick-start {
            background: rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
        }

        .quick-start h3 {
            margin-bottom: 1rem;
        }

        .cmd {
            background: #1a1a2e;
            padding: 1rem;
            border-radius: 8px;
            font-family: monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            margin: 1rem 0;
        }

        /* 链接按钮 */
        .btn {
            display: inline-block;
            background: #fff;
            color: #667eea;
            padding: 0.8rem 1.5rem;
            border-radius: 30px;
            text-decoration: none;
            font-weight: 600;
            margin: 0.5rem;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
        }

        .btn-outline {
            background: transparent;
            color: #fff;
            border: 1px solid rgba(255,255,255,0.3);
        }

        .btn-outline:hover {
            background: rgba(255,255,255,0.1);
        }

        .buttons {
            text-align: center;
            margin-bottom: 2rem;
        }

        /* 底部 */
        .footer {
            text-align: center;
            padding-top: 2rem;
            margin-top: 2rem;
            border-top: 1px solid rgba(255,255,255,0.2);
            font-size: 0.8rem;
            opacity: 0.7;
        }

        .footer a {
            color: #fff;
            text-decoration: none;
        }

        .footer a:hover {
            text-decoration: underline;
        }

        /* 响应式 */
        @media (max-width: 600px) {
            .container {
                padding: 2rem 1rem;
            }
            h1 {
                font-size: 1.8rem;
            }
            .features {
                grid-template-columns: 1fr;
            }
        }

        /* 对比表格 */
        .comparison {
            background: rgba(0,0,0,0.3);
            border-radius: 16px;
            overflow-x: auto;
            margin-bottom: 2rem;
        }

        .comparison table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }

        .comparison th,
        .comparison td {
            padding: 0.8rem 1rem;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }

        .comparison th {
            background: rgba(255,255,255,0.1);
            font-weight: 600;
        }

        .check {
            color: #00ff9d;
        }

        .cross {
            color: #ff6b6b;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 头部 -->
        <div class="header">
            <div class="logo">🛡️</div>
            <h1>CoolGate</h1>
            <div class="tagline">零数据认证网关 · 让爬虫冷静，让网站自由</div>
            <div class="badge">
                <a href="#">GitHub</a>
                <a href="#">Go 1.21+</a>
                <a href="#">MIT License</a>
                <a href="#">生产可用</a>
            </div>
        </div>

        <!-- 按钮 -->
        <div class="buttons">
            <a href="https://github.com/zhiliaoya" class="btn">⭐ GitHub</a>
            <a href="#quick-start" class="btn btn-outline">🚀 快速开始</a>
            <a href="#docs" class="btn btn-outline">📖 文档</a>
        </div>

        <!-- 特性 -->
        <div class="features">
            <div class="feature-card">
                <div class="feature-icon">🔒</div>
                <div class="feature-title">零数据存储</div>
                <div class="feature-desc">不存储任何用户数据，OpenID 验证即焚，天然符合 GDPR 和个保法要求。</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon">⚡</div>
                <div class="feature-title">PoW 防爬虫</div>
                <div class="feature-desc">工作量证明机制，让每次请求都需要算力，爬虫成本提高 1000 倍。</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon">📱</div>
                <div class="feature-title">微信扫码</div>
                <div class="feature-desc">12 亿用户覆盖，扫码即登录，无需密码，无需注册。</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🚀</div>
                <div class="feature-title">开箱即用</div>
                <div class="feature-desc">Docker 一键部署，5 分钟接入现有业务，改 3 行代码即可。</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🛡️</div>
                <div class="feature-title">多层防御</div>
                <div class="feature-desc">IP 封禁 + 设备指纹 + 限流 + 一次性令牌 + PoW + 扫码验证</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🌐</div>
                <div class="feature-title">透明代理</div>
                <div class="feature-desc">对后端透明，通过 Header 传递用户 ID，任何语言都能接入。</div>
            </div>
        </div>

        <!-- 对比表格 -->
        <div class="section-title">与传统方案对比</div>
        <div class="section-subtitle">看看 CoolGate 如何改变游戏规则</div>
        <div class="comparison">
            <table>
                <thead>
                    <tr>
                        <th>对比项</th>
                        <th>传统 WAF</th>
                        <th>CoolGate</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td>防护原理</td><td>规则匹配</td><td>经济成本</td></tr>
                    <tr><td>用户数据存储</td><td>是</td><td class="check">否 ✓</td></tr>
                    <tr><td>爬虫防护成本</td><td>高</td><td class="check">低 ✓</td></tr>
                    <tr><td>用户体验</td><td>验证码烦人</td><td class="check">无感 ✓</td></tr>
                    <tr><td>零日攻击防护</td><td class="cross">✗</td><td class="check">✓</td></tr>
                    <tr><td>合规成本</td><td>高</td><td class="check">低 ✓</td></tr>
                    <tr><td>部署时间</td><td>数天</td><td class="check">5 分钟 ✓</td></tr>
                </tbody>
            </table>
        </div>

        <!-- 快速开始 -->
        <div class="quick-start" id="quick-start">
            <h3>🚀 快速开始</h3>
            
            <p>就这么简单！你的网站现在已经拥有企业级防护。</p>
        </div>

        <!-- 接入方式 -->
        <div class="section-title">📦 接入方式</div>
        <div class="section-subtitle">无论什么技术栈，3 行代码搞定</div>
        <div class="code-block">
            <pre>
# Python / Flask
user_id = request.headers.get('X-User-ID')

# Node.js / Express
const userId = req.headers['x-user-id'];

# Go / Gin
userID := c.Request.Header.Get("X-User-ID")

# PHP / Laravel
$userId = $request->header('X-User-ID');</pre>
        </div>

        <!-- 开源协议 -->
        <div class="footer">
            <p>© 2026 | 开源协议：MIT | 代码完全开源，欢迎 PR</p>
            <p>
                <a href="https://github.com/zhilaioya">GitHub</a> |
                <a href="#">文档</a> |
                <a href="#">Issues</a> |
                <a href="#">讨论区</a>
            </p>
        </div>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprint(w, html)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"service":   "web-service",
		"timestamp": time.Now().Format(time.RFC3339),
		"uptime":    time.Since(startTime).String(),
	})
}

func handleAPIInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"service":   "gateway-demo",
		"version":   "1.0.0",
		"name":      "CoolGate - Zero Data Auth Gateway",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func handleAPITime(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"unix":      time.Now().Unix(),
		"timezone":  "Asia/Shanghai",
		"datetime":  time.Now().Format("2006-01-02 15:04:05"),
	})
}