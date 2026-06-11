## HongJie - 轻量化微信认证网关

### 项目声明

> **🤖 AI 生成声明**
>
> 本项目代码的 **90% 以上由 DeepSeek 生成**，少量错误逻辑和边界问题由 **Claude 进行纠正和优化**。
>
> 作者角色：
> - 🏗️ 项目框架设计
> - ⚙️ 环境部署与配置
> - 🧪 运行测试与 Bug 反馈
> - 🔄 人机协作流程协调
>
> 这是一个典型的 **AI 辅助编程实践项目**，展示了当前大语言模型在复杂业务系统开发中的能力与局限性。通过人机协作，大幅提升了开发效率，同时保证了代码质量。

---

## 项目简介

HongJie 是一个基于 Go 语言开发的轻量化微信认证网关，通过微信小程序扫码实现网站身份认证，无需存储用户敏感数据，天然符合 GDPR 和个保法要求。采用多层防御机制（PoW 工作量证明 + IP 封禁 + 设备指纹限流 + Cloudflare Turnstile + 一次性动态链路），有效抵御爬虫攻击。

### 应用案例
作者私人博客：https://zhiliaoya.cn/
## 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                        用户浏览器                            │
│   ┌─────────┐    ┌─────────┐    ┌─────────┐                │
│   │ 登录页  │ -> │ 二维码  │ -> │ 轮询状态│                │
│   └─────────┘    └─────────┘    └─────────┘                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    HongJie Gateway (Go)                      │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    防御层                            │    │
│  │  IP封禁 → PoW挑战 → Turnstile → 限流 → 一次性令牌   │    │
│  └─────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    业务层                            │    │
│  │  场景管理 → 令牌交换 → 代理转发 → Cookie管理        │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                    │                    │
                    ▼                    ▼
          ┌──────────────┐      ┌──────────────┐
          │  微信小程序   │      │  后端Web服务  │
          │  (扫码授权)   │      │  (业务处理)   │
          └──────────────┘      └──────────────┘
```

## 目录结构

```
HongJie/
├── WebService/                    # 服务端代码
│   ├── docker-compose.yml         # Docker 编排文件
│   ├── static/                    # 静态资源目录
│   │   └── image/                 # 图片资源
│   │       ├── favicon.ico
│   │       ├── logo.png
│   │       └── loading.gif
│   └── app/
│       └── go/
│           ├── gateway/           # 网关服务（主程序）
│           │   ├── main.go        # 网关入口
│           │   └── static_files.json  # 静态文件配置
│           └── web/               # 示例 Web 服务
│               └── main.go        # 后端示例程序
│
└── WxApp/                         # 微信小程序代码
    ├── app.js                     # 小程序入口
    ├── app.json                   # 小程序配置
    ├── app.wxss                   # 全局样式
    ├── project.config.json        # 项目配置
    ├── sitemap.json               # 站点地图
    └── pages/
        ├── index/                 # 授权确认页
        │   ├── index.js
        │   ├── index.wxml
        │   ├── index.wxss
        │   └── index.json
        └── end/                   # 结果页
            ├── end.js
            ├── end.wxml
            ├── end.wxss
            └── end.json
```

## 核心功能

### 1. 网关服务 (Gateway)

| 功能模块 | 说明 |
|---------|------|
| **用户认证** | 微信扫码登录，支持一次性动态链路 |
| **多层防御** | IP封禁、PoW工作量证明、Turnstile人机验证、设备指纹限流 |
| **透明代理** | 向后端转发请求，通过 Header 传递用户身份 |
| **静态文件服务** | 支持配置静态文件路径和缓存策略 |
| **Cookie管理** | HttpOnly Secure Cookie 存储认证令牌 |

### 2. 微信小程序

| 页面 | 功能 |
|------|------|
| **授权页** | 展示登录确认/取消按钮，获取微信 code 并回调网关 |
| **结果页** | 显示登录结果，支持关闭小程序 |

## 快速开始

### 前置要求

- Go 1.21+
- Docker & Docker Compose（可选）
- 微信小程序 AppID 和 AppSecret
- 域名及 SSL 证书（Let's Encrypt 推荐）
- Cloudflare Turnstile 站点密钥（可选）

### 1. 配置修改

编辑 `WebService/app/go/gateway/main.go`：

```go
var (
    wechatAppID     = "your_wechat_appid"
    wechatAppSecret = "your_wechat_secret"
    
    certPath = "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
    keyPath  = "/etc/letsencrypt/live/your-domain.com/privkey.pem"
    
    webServiceURL    = "http://web-service:80"
    staticConfigPath = "static_files.json"
    
    cfTurnstileSecret  = "your_turnstile_secret"
    cfTurnstileSiteKey = "your_turnstile_site_key"
)
```

### 2. Docker 部署

```bash
cd WebService

# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f gateway-service
```

### 3. 小程序配置

1. 在微信公众平台将小程序服务器域名配置为你的网关域名
2. 修改 `WxApp/project.config.json` 中的 AppID
3. 使用微信开发者工具上传代码

### 4. 后端接入示例

任何语言的后端服务只需读取请求头即可获取用户信息：

```go
// Go
userID := r.Header.Get("X-User-ID")
openID := r.Header.Get("X-Open-ID")
```

```python
# Python Flask
user_id = request.headers.get('X-User-ID')
```

```javascript
// Node.js
const userId = req.headers['x-user-id'];
```

```php
// PHP
$userId = $_SERVER['HTTP_X_USER_ID'];
```

## API 接口文档

### 公开接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/login` | GET | 登录页面 |
| `/api/qr-challenge` | GET | 获取 PoW 挑战 |
| `/api/qr` | POST | 生成二维码（含完整防御） |
| `/api/status` | GET | 查询场景状态 |
| `/api/ws` | GET | SSE 状态推送 |
| `/api/exchange-token` | POST | 交换认证令牌 |

### 动态链路接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/{scene_token}` | POST | 小程序回调验证（一次性） |

### 管理接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/admin/suspicious` | GET | 查看可疑行为日志（仅内网） |
| `/health` | GET | 健康检查 |

## 安全机制说明

### 第一层：IP 封禁
- 根据违规次数动态封禁（5次→10分钟，10次→1小时，20次→24小时）
- 定期清理过期封禁记录

### 第二层：PoW 工作量证明
- 每次二维码请求前需完成 SHA-256 计算
- 难度 16 bit，有效防止自动化脚本

### 第三层：Cloudflare Turnstile
- 可选的人机验证，进一步识别机器人

### 第四层：设备指纹限流
- 基于 IP + 设备指纹的 60 秒冷却
- 防止同设备/同 IP 高频请求

### 第五层：一次性动态链路
- 每个二维码携带唯一令牌（32 位 hex）
- 60 秒有效期，使用即失效

## 数据流时序图

```
浏览器                网关                 微信服务器              小程序              后端服务
   │                   │                      │                    │                   │
   │   GET /login      │                      │                    │                   │
   │──────────────────>│                      │                    │                   │
   │                   │                      │                    │                   │
   │   PoW挑战+二维码   │                      │                    │                   │
   │<──────────────────│                      │                    │                   │
   │                   │                      │                    │                   │
   │   POST /api/qr    │                      │                    │                   │
   │  (PoW+Turnstile)  │                      │                    │                   │
   │──────────────────>│                      │                    │                   │
   │                   │  生成scene_token      │                    │                   │
   │                   │  返回二维码+scene_id  │                    │                   │
   │<──────────────────│                      │                    │                   │
   │                   │                      │                    │                   │
   │   SSE轮询状态     │                      │  用户扫码          │                   │
   │──────────────────>│                      │<───────────────────│                   │
   │                   │                      │                    │                   │
   │                   │   POST /api/{token}   │                    │                   │
   │                   │<─────────────────────────────────────────│                   │
   │                   │   ?code=xxx          │                    │                   │
   │                   │                      │                    │                   │
   │                   │  jscode2session      │                    │                   │
   │                   │─────────────────────>│                    │                   │
   │                   │  return openid       │                    │                   │
   │                   │<─────────────────────│                    │                   │
   │                   │                      │                    │                   │
   │                   │  更新场景状态为confirmed│                    │                   │
   │                   │                      │                    │                   │
   │   状态更新(confirmed)│                    │                    │                   │
   │<──────────────────│                      │                    │                   │
   │                   │                      │                    │                   │
   │   POST /api/exchange-token               │                    │                   │
   │──────────────────>│                      │                    │                   │
   │                   │  生成auth_token       │                    │                   │
   │                   │  Set-Cookie           │                    │                   │
   │<──────────────────│                      │                    │                   │
   │                   │                      │                    │                   │
   │   后续请求(带Cookie)│                      │                    │                   │
   │──────────────────>│                      │                    │                   │
   │                   │  验证auth_token       │                    │                   │
   │                   │  代理转发 + Header    │                    │                   │
   │                   │───────────────────────────────────────────────────────────>│
   │                   │                      │                    │                   │
   │   响应            │                      │                    │                   │
   │<───────────────────────────────────────────────────────────────────────────────│
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `TZ` | 时区 | `Asia/Shanghai` |
| `GO111MODULE` | Go 模块 | `on` |
| `GOPROXY` | Go 代理 | `https://goproxy.cn,direct` |
| `SERVICE_NAME` | 服务名称 | `gateway` / `web` |

## 常见问题

### Q: 如何更新微信 access_token？
A: 网关会自动定时刷新（提前 300 秒），无需手动干预。

### Q: 小程序码的有效期是多久？
A: 二维码本身是微信生成的长期有效码，但对应的 `scene_token` 有效期为 60 秒，超时需重新获取。

### Q: 如何自定义静态文件？
A: 修改 `static_files.json` 添加路径映射，文件需放在容器内对应路径。

### Q: 后端服务如何获取用户 OpenID？
A: 网关会在代理请求中添加 `X-Open-ID` Header。

## 技术栈

| 组件 | 技术 |
|------|------|
| 网关语言 | Go 1.21+ |
| 容器化 | Docker + Docker Compose |
| 小程序 | 微信小程序原生框架 |
| 安全 | Cloudflare Turnstile + SHA-256 PoW |
| 证书 | Let's Encrypt (自动续期) |

## AI 贡献详情

| AI 模型 | 贡献内容 | 占比 |
|---------|----------|------|
| **DeepSeek** | 核心逻辑实现、框架搭建、API 设计、前端页面、小程序代码 | ~90% |
| **Claude** | 错误逻辑修复、边界条件处理、代码优化、安全性增强 | ~10% |

**人机协作流程**：
1. 作者设计整体架构和业务流程
2. DeepSeek 生成主要代码实现
3. 作者进行环境部署和运行测试
4. 发现 Bug 后反馈给 Claude 进行修正
5. 循环迭代直至功能完善

## License

MIT License

## 贡献指南

欢迎提交 Issue 和 Pull Request

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing`)
5. 提交 Pull Request

## 致谢

- [DeepSeek](https://deepseek.com) - 核心代码生成
- [Claude](https://anthropic.com/claude) - 代码纠错与优化
- [微信开放平台](https://developers.weixin.qq.com/) - 小程序能力支持
- [Cloudflare](https://cloudflare.com) - Turnstile 人机验证服务

---

**HongJie** - 让爬虫冷静，让网站自由 🛡️

*本项目是 AI 辅助编程的实践成果，展示了人机协作的高效开发模式。*
