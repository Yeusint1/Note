package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"image"
	"io"
	"math/rand"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"time"

	"github.com/carlmjohnson/requests"
	"github.com/fogleman/gg"
	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/opentype"
)

func genKey(length int) string {
	if length <= 0 {
		length = 16
	}
	const s = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = s[rand.Intn(len(s))]
	}
	return string(b)
}

// createCode creates a simple PNG and returns the image bytes and the verification string
func createCode(a, b int) ([]byte, string, error) {
	f, err := os.Open("code.png")
	if err != nil {
		panic(err)
	}
	i, _, err := image.Decode(f)
	f.Close()
	if err != nil {
		panic(err)
	}
	img := gg.NewContextForImage(i)

	face, _ := loadFont(35)
	img.SetFontFace(face)
	img.SetRGB(0, 0, 1)
	img.DrawString(strconv.Itoa(a), 2, 35)
	img.SetRGB(0, 1, 0)
	img.DrawString(strconv.Itoa(b), 60, 35)

	var buf bytes.Buffer
	err = img.EncodePNG(&buf)

	return buf.Bytes(), calculateCode(a, b), err
}

func calculateCode(a, b int) string {
	sum := a + b
	c := strconv.Itoa(sum)

	// 确保有至少两位数字
	if len(c) < 2 {
		c = "0" + c // 如果只有一位，前面补0
	}

	// 计算验证码逻辑：str(int(c[0])+1)[-1] + str(int(c[1])+5)[-1]
	firstDigit, _ := strconv.Atoi(string(c[0]))
	secondDigit, _ := strconv.Atoi(string(c[1]))

	return strconv.Itoa((firstDigit+1)%10) + strconv.Itoa((secondDigit+5)%10)
}

func loadFont(size float64) (font.Face, error) {
	_font, err := opentype.Parse(goregular.TTF)
	if err != nil {
		return nil, err
	}

	face, err := opentype.NewFace(_font, &opentype.FaceOptions{
		Size:    size,
		DPI:     72,
		Hinting: font.HintingFull,
	})
	return face, err
}

func loadMemos() error {
	memosMu.Lock()
	defer memosMu.Unlock()
	if _, err := os.Stat(memosFile); os.IsNotExist(err) {
		// create empty file
		if err := os.WriteFile(memosFile, []byte("{}"), 0644); err != nil {
			return err
		}
		memos = map[int]Memo{}
		return nil
	}
	b, err := os.ReadFile(memosFile)
	if err != nil {
		return err
	}
	var raw map[string]Memo
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	memos = map[int]Memo{}
	for k, v := range raw {
		i, err := strconv.Atoi(k)
		if err != nil {
			continue
		}
		memos[i] = v
	}
	return nil
}

func saveMemos() error {
	memosMu.RLock()
	defer memosMu.RUnlock()
	raw := map[string]Memo{}
	for k, v := range memos {
		raw[strconv.Itoa(k)] = v
	}
	b, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(memosFile, b, 0644)
}

func cleanExpiredCodes() {
	authMu.Lock()
	defer authMu.Unlock()
	now := time.Now().Unix()
	for k, v := range authCode {
		if v.Expire < now {
			delete(authCode, k)
		}
	}
}

func checkKey(key string) (bool, string) {

	authMu.RLock()
	expire, ok := authKey[key]
	authMu.RUnlock()
	if !ok {
		return false, "key not found"
	}
	if expire < time.Now().Unix() {
		authMu.Lock()
		delete(authKey, key)
		authMu.Unlock()
		return false, "key expired"
	}
	return true, "ok"
}

func checkOAKey(key string) (bool, string) {

	oauthMu.RLock()
	info, ok := oauthKey[key]
	oauthMu.RUnlock()
	if !ok {
		return false, "key not found"
	}
	if info.AccessExpire.Unix() < time.Now().Unix() {
		req := map[string]any{
			"grant_type": "refresh_token",
			"refresh":    info.RefreshToken,
		}

		var res struct {
			Code uint8 `json:"code"`
			Data struct {
				Uid    int    `json:"uid"`
				Access string `json:"access_token"`
				Expire uint16 `json:"expires_in"`
			} `json:"data"`
		}

		con := context.Background()

		// 令牌
		err := requests.
			URL("/api/oauth/token").
			Host("auth.overpass.top").
			Header("Authorization", `Bearer `+OAuthSecret).
			BodyJSON(&req).
			ToJSON(&res).
			Fetch(con)
		if err != nil {
			return false, "Can't gain key"

		}
		if res.Code != 0 {
			return false, "Code not match"
		}

		info.AccessExpire = time.Now().Add(time.Duration(res.Data.Expire) * time.Second)
		info.AccessToken = res.Data.Access
		oauthMu.Lock()
		oauthKey[key] = info
		oauthMu.Unlock()
	}
	return true, "ok"
}

// small helper
func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// EmailConfig 邮件配置结构体
type EmailConfig struct {
	SMTPHost     string   `json:"smtp_host"`
	SMTPPort     int      `json:"smtp_port"`
	FromEmail    string   `json:"from_email"`
	FromPassword string   `json:"from_password"`
	ToEmail      []string `json:"to_email"`
}
type EmailTemplate struct {
	Title      string
	CreateTime string
	Text       string
	HasFiles   bool
	Files      []struct {
		Name string
		ID   string
	}
}

type EmailRequest struct {
	Target string            `json:"recipient"`
	Attrib map[string]string `json:"attribs"`
}

// SendEmail 发送邮件函数
func SendEmail(config EmailConfig, subject, body string) error {

	// SMTP服务器地址
	smtpAddr := fmt.Sprintf("%s:%d", config.SMTPHost, config.SMTPPort)

	// 认证信息
	auth := smtp.PlainAuth("", config.FromEmail, config.FromPassword, config.SMTPHost)

	conn, err := tls.Dial("tcp", smtpAddr, &tls.Config{
		ServerName:         config.SMTPHost,
		InsecureSkipVerify: false,
	})
	if err != nil {
		fmt.Printf("SSL: %v", err)
		return err
	}
	defer conn.Close()
	c, err := smtp.NewClient(conn, config.SMTPHost)
	if err != nil {
		fmt.Printf("创建SMTP客户端失败: %v", err)
		return err
	}
	defer c.Quit()
	if err = c.Auth(auth); err != nil {
		return err
	}
	if err = c.Mail(config.FromEmail); err != nil {
		return err
	}
	for _, addr := range config.ToEmail {
		if err = c.Rcpt(addr); err != nil {
			return err
		}
	}

	w, err := c.Data()
	if err != nil {
		fmt.Printf("准备写入邮件数据失败: %v", err)
		return err
	}
	_, err = w.Write([]byte(fmt.Sprintf("From: %s\r\n", config.FromEmail) +
		fmt.Sprintf("Subject: %s\r\n", subject) +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" +
		body))
	if err != nil {
		fmt.Printf("写入邮件数据失败: %v", err)
		return err
	}
	err = w.Close()
	if err != nil {
		fmt.Printf("Failed to close: %v", err)
		return err
	}
	return nil
}

// SendMemoEmail 发送备忘录邮件
func SendMemoEmail(config EmailConfig, memo Memo) error {
	subject := fmt.Sprintf("Note sync: %s", memo.Title)

	em := EmailTemplate{
		Title:      memo.Title,
		Text:       memo.Text,
		CreateTime: time.Unix(memo.Time, 0).Add(time.Hour * 8).Format("2006-01-02 15:04:05"),
		HasFiles:   len(memo.File) > 0,
	}
	if em.HasFiles {
		file := []struct {
			Name string
			ID   string
		}{}
		for fileID, fileName := range memo.File {
			file = append(file, struct {
				Name string
				ID   string
			}{fileName, fileID})
		}
		em.Files = file
	}

	tl, err := template.ParseFiles("./mail.htm")
	if err != nil {
		fmt.Printf("mail.htm: %v", err)
		return err
	}
	var body bytes.Buffer
	if err := tl.Execute(&body, em); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	return SendEmail(config, subject, body.String())
}

func SendEmail2(memo Memo, recipient string) error {
	attrib := map[string]string{}
	if len(memo.File) == 0 {
		attrib = map[string]string{
			"title":   memo.Title,
			"time":    time.Unix(memo.Time, 0).Add(time.Hour * 8).Format("2006-01-02 15:04:05"),
			"text":    memo.Text,
			"HasFile": "否",
		}
	} else {
		attrib = map[string]string{
			"title":   memo.Title,
			"time":    time.Unix(memo.Time, 0).Add(time.Hour * 8).Format("2006-01-02 15:04:05"),
			"text":    memo.Text,
			"HasFile": "是",
		}
	}
	data := EmailRequest{
		Target: recipient,
		Attrib: attrib,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Mail2 send error(json): %s", err)
		return err
	}

	req, err := http.NewRequest("POST", "https://mail.overpass.top:41443/api/batch_mail/api/send", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Mail2 send error(newRequest): %s", err)
		return err

	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "e23291238e8790e507da7e89b9f922b0fb1d8c023afe007b6807170d6d316b4d")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Mail2 send error(client do): %s", err)
		return err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Mail2 send error(read body): %s", err)
		return err
	}
	fmt.Printf("Mail2 send result: %s", string(body))

	return nil
}
