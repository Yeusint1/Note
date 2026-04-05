package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

func RateLimiter(r rate.Limit, burst int) gin.HandlerFunc {
	limiter := rate.NewLimiter(r, burst)
	return func(c *gin.Context) {
		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
			return
		}
		c.Next()
	}
}

// ----- Data structures and globals -----

type Memo struct {
	Title string            `json:"title"`
	Text  string            `json:"text"`
	File  map[string]string `json:"file"`
	Time  int64             `json:"time"`
	Label []Label           `json:"label"`
}

type Label struct {
	Display  string `json:"display"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	RelateId int    `json:"relate,omitempty"`
}

type UserInfo struct {
	Id           uint32 `json:"id"`
	Name         string `json:"name"`
	Mail         string `json:"mail"`
	AccessToken  string `json:"access_token"`
	AccessExpire time.Time
	RefreshToken string `json:"refresh_token"`
}

type AuthCode struct {
	Answer string
	Expire int64
}

var (
	OAuthSecret = os.Getenv("OAUTH_SECRET")
	memos       = map[int]Memo{}
	memosMu     sync.RWMutex

	authCode = map[string]AuthCode{}
	authKey  = map[string]int64{}
	oauthKey = map[string]UserInfo{}
	authMu   sync.RWMutex
	oauthMu  sync.RWMutex

	emailConfig EmailConfig
)

const memosFile = "memos.json"

func loadEmailConfig() {
	// 从环境变量加载邮件配置
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPortStr := os.Getenv("SMTP_PORT")
	fromEmail := os.Getenv("FROM_EMAIL")
	fromPassword := os.Getenv("FROM_PASSWORD")
	toEmail := strings.Split(os.Getenv("TO_EMAIL"), ",")

	// 验证必要的配置
	if smtpHost == "" || smtpPortStr == "" || fromEmail == "" || fromPassword == "" || toEmail == nil {
		fmt.Fprintf(os.Stderr, "邮件配置不完整，邮件同步功能已禁用\n")
		return
	}

	// 转换端口号
	smtpPort, err := strconv.Atoi(smtpPortStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SMTP端口号无效: %v\n", err)
		return
	}

	// 设置邮件配置
	emailConfig = EmailConfig{
		SMTPHost:     smtpHost,
		SMTPPort:     smtpPort,
		FromEmail:    fromEmail,
		FromPassword: fromPassword,
		ToEmail:      toEmail,
	}

	fmt.Printf("邮件同步功能已启用，目标邮箱: %s\n", toEmail)
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.Use(RateLimiter(30, 10))

	r.Static("/assets", "./dist/assets")

	files, err := os.ReadDir("./dist")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	for _, f := range files {
		if !f.IsDir() {
			fmt.Println("Static: " + f.Name())
			r.StaticFile("/"+f.Name(), "./dist/"+f.Name())
		}
	}

	// load memos from disk
	if err := loadMemos(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to load memos.json: %v\n", err)
	}

	r.LoadHTMLFiles("./back.htm")

	api := r.Group("/api")
	{
		api.GET("/code", codeHandler)
		api.POST("/authorize", authorizeHandler)
		api.POST("/verify", verifyHandler)
		api.GET("/memo", memoGetHandler)
		api.POST("/memo", memoPostHandler)
		api.DELETE("/memo/:id", memoDeleteHandler)
		api.GET("/download", downloadHandler)
		api.POST("/sync", syncHandler)
		api.GET("/getUser", UserInfoHandler)
	}

	r.GET("/oauth/authorize", OAuthCallbackHandler)

	r.NoRoute(func(ctx *gin.Context) {
		if ctx.Request.Header.Get("Accept") == "application/json" {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Not Found"})
			return
		}
		ctx.File("./dist/index.html")
	})

	// 加载邮件配置
	loadEmailConfig()

	if os.Getenv("SSL_ENABLE") == "1" {
		r.RunTLS(":8081", "./ser.pem", "./ser.key")
	} else {
		r.Run(":8081")
	}
}
