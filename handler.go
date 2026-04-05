package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/carlmjohnson/requests"
	"github.com/gin-gonic/gin"
)

func codeHandler(c *gin.Context) {
	a := rand.Intn(46) + 5 // 5..50
	b := rand.Intn(45) + 5 // 5..49
	imgBytes, ans, err := createCode(a, b)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "create code fail"})
		return
	}
	codeID := genKey(8)
	authMu.Lock()
	authCode[codeID] = AuthCode{Answer: ans, Expire: time.Now().Add(5 * time.Minute).Unix()}
	authMu.Unlock()
	cleanExpiredCodes()
	c.Header("X-Code-Id", codeID)
	c.Data(http.StatusOK, "image/png", imgBytes)
}

func authorizeHandler(c *gin.Context) {
	var codeID, code string
	if c.Request.Header.Get("Content-Type") == "application/json" {
		var body map[string]string
		if err := c.BindJSON(&body); err == nil {
			codeID = body["code_id"]
			code = body["code"]
		}
	}
	if codeID == "" {
		codeID = c.PostForm("code_id")
	}
	if code == "" {
		code = c.PostForm("code")
	}
	if codeID == "" || code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "code_id or code is empty"})
		return
	}
	authMu.Lock()
	cd, ok := authCode[codeID]
	if !ok {
		authMu.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "code_id not found or expired"})
		return
	}
	if cd.Expire < time.Now().Unix() {
		delete(authCode, codeID)
		authMu.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "code expired"})
		return
	}
	if cd.Answer != code {
		authMu.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "code not match"})
		return
	}
	delete(authCode, codeID)
	// create key
	key := genKey(16)
	expire := time.Now().Unix() + int64(rand.Intn(604800-259200)+259200)
	authKey[key] = expire
	authMu.Unlock()
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "ok", "key": key, "expired": expire})
}

func verifyHandler(c *gin.Context) {

	var code string
	if c.Request.Header.Get("Content-Type") == "application/json" {
		var body map[string]string
		if err := c.BindJSON(&body); err == nil {
			code = body["code"]
		}
	}
	if code == "" {
		code = c.PostForm("code")
	}
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "key is empty"})
		return
	}
	ok, msg := checkKey(code)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": msg})
		return
	}
	ok, msg = checkOAKey(code)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": msg})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "ok"})
}

func memoGetHandler(c *gin.Context) {
	key := c.GetHeader("X-Key")
	if key == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "key is empty"})
		return
	}
	ok, msg := checkKey(key)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": msg})
		return
	}
	ok, msg = checkOAKey(key)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": msg})
		return
	}
	// ↑验证阶段

	idStr := c.Query("id")
	if idStr != "" {
		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "id invalid"})
			return
		}
		memosMu.RLock()
		memo, ok := memos[id]
		memosMu.RUnlock()
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"code": 404, "msg": "id not found"})
			return
		}
		files := []gin.H{}
		for k, v := range memo.File {
			files = append(files, gin.H{"id": k, "name": v})
		}
		c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "ok", "id": idStr, "title": memo.Title, "text": memo.Text, "file": files, "time": memo.Time, "label": memo.Label})
		return
	}
	// list memos
	memosMu.RLock()
	ids := make([]int, 0, len(memos))
	for id := range memos {
		ids = append(ids, id)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(ids)))
	list := []gin.H{}
	for _, id := range ids {
		list = append(list, gin.H{"id": id, "title": memos[id].Title, "time": memos[id].Time})
	}
	memosMu.RUnlock()
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "ok", "memo": list})
}

func memoDeleteHandler(c *gin.Context) {
	key := c.GetHeader("X-Key")
	if key == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "key is empty"})
		return
	}
	ok, msg := checkKey(key)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": msg})
		return
	}
	ok, msg = checkOAKey(key)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": msg})
		return
	}

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "id invalid"})
		return
	}
	memosMu.Lock()
	delete(memos, id)
	memosMu.Unlock()
	if err := saveMemos(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "save fail"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "ok"})
}

func memoPostHandler(c *gin.Context) {
	key := c.GetHeader("X-Key")
	if key == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "key is empty"})
		return
	}
	ok, msg := checkKey(key)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": msg})
		return
	}
	ok, msg = checkOAKey(key)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": msg})
		return
	}

	title := c.PostForm("title")
	text := c.PostForm("text")
	// handle files (may be multiple)
	filesMap := map[string]string{}
	labels := []Label{}
	if c.Request.MultipartForm == nil {
		// try to parse multipart form
		_ = c.Request.ParseMultipartForm(32 << 20)
	}
	if c.Request.MultipartForm != nil && len(c.Request.MultipartForm.File) > 0 {
		if _, err := os.Stat("files"); os.IsNotExist(err) {
			_ = os.Mkdir("files", 0755)
		}
		for _, fhs := range c.Request.MultipartForm.File {
			for _, fh := range fhs {
				r, err := fh.Open()
				if err != nil {
					continue
				}
				data, err := io.ReadAll(r)
				r.Close()
				if err != nil {
					continue
				}
				md := md5.Sum(data)
				md5s := hex.EncodeToString(md[:])
				fp := filepath.Join("files", md5s)
				_ = os.WriteFile(fp, data, 0644)
				filesMap[md5s] = fh.Filename
			}
		}
	}
	if label := c.PostForm("label"); label != "" {
		println(label)
		err := json.Unmarshal([]byte(label), &labels)
		if err != nil {
			fmt.Println(err.Error())
			c.JSON(400, gin.H{"code": 400, "msg": "invaild label"})
			return
		}
	}
	if title == "" || (text == "" && len(filesMap) == 0) {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "title or data is empty"})
		return
	}
	memosMu.Lock()
	maxID := 0
	for k := range memos {
		if k > maxID {
			maxID = k
		}
	}
	memoID := maxID + 1
	newMemo := Memo{Title: title, Text: text, File: filesMap, Time: time.Now().Unix(), Label: labels}
	memos[memoID] = newMemo
	memosMu.Unlock()
	if err := saveMemos(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "save fail"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "ok", "id": memoID})
	if sync := c.PostForm("mail_sync"); sync == "true" {
		if err := SendMemoEmail(emailConfig, newMemo); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"code": 500,
				"msg":  "Mail: " + err.Error(),
			})
		} else {
			fmt.Printf("Mail send err: %s", err)
		}
		for _, addr := range emailConfig.ToEmail {
			SendEmail2(newMemo, addr)
		}

	}
}

func downloadHandler(c *gin.Context) {
	key := c.GetHeader("X-Key")
	if key == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "key is empty"})
		return
	}
	ok, msg := checkKey(key)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": msg})
		return
	}
	ok, msg = checkOAKey(key)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": msg})
		return
	}

	id := c.Query("id")
	mid := c.Query("mid")
	if id == "" || mid == "" || !isDigits(mid) {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "id is empty"})
		return
	}
	mID, _ := strconv.Atoi(mid)
	memosMu.RLock()
	memo, ok := memos[mID]
	memosMu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "msg": "id not found"})
		return
	}
	if fname, ok := memo.File[id]; ok {
		fp := filepath.Join("files", id)
		if _, err := os.Stat(fp); err == nil {
			if c.Query("save") != "" {
				// force attachment
				c.Header("Content-Transfer-Encoding", "binary")
				c.FileAttachment(fp, fname)
				return
			}
			c.File(fp)
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "msg": "file not found"})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "no file"})
}

func syncHandler(c *gin.Context) {
	if c.Request.Header.Get("Passkey") != "0ED68387D966FA2C" {
		c.JSON(http.StatusForbidden, gin.H{"status": 403, "message": "json data required"})
		return
	}
	var req map[string]interface{}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 403, "message": "json data required"})
		return
	}
	l, ok := req["last_sync"]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"status": 402, "message": "last_sync error"})
		return
	}
	lsf, ok := l.(float64)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"status": 402, "message": "last_sync error"})
		return
	}
	lastSync := int(lsf)
	memosMu.RLock()
	maxKey := 0
	for k := range memos {
		if k > maxKey {
			maxKey = k
		}
	}
	memosMu.RUnlock()
	if !((lastSync == 0 && len(memos) == 0) || (len(memos) > 0 && 0 <= lastSync && lastSync <= maxKey)) {
		c.JSON(http.StatusBadRequest, gin.H{"status": 402, "message": "last_sync out of range"})
		return
	}
	push, ok := req["push"]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"status": 401, "message": "push can not be null"})
		return
	}
	pushList, ok := push.([]interface{})
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"status": 401, "message": "push format error"})
		return
	}
	// Validate push format (each item must have ts, title, content/text)
	for _, item := range pushList {
		m, ok := item.(map[string]interface{})
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"status": 401, "message": "push format error"})
			return
		}
		if _, a := m["ts"]; !a {
			c.JSON(http.StatusBadRequest, gin.H{"status": 401, "message": "push format error"})
			return
		}
		if _, a := m["title"]; !a {
			c.JSON(http.StatusBadRequest, gin.H{"status": 401, "message": "push format error"})
			return
		}
		if _, a := m["content"]; !a {
			c.JSON(http.StatusBadRequest, gin.H{"status": 401, "message": "push format error"})
			return
		}
	}
	// prepare returning data: memos with id > lastSync
	rdata := map[string]map[string]interface{}{}
	memosMu.RLock()
	for k, v := range memos {
		if k > lastSync {
			rdata[strconv.Itoa(k)] = map[string]interface{}{"title": v.Title, "content": v.Text, "time": v.Time}
		}
	}
	memosMu.RUnlock()
	// append pushed items
	added := []int{}
	memosMu.Lock()
	for _, item := range pushList {
		m := item.(map[string]interface{})
		tsf := m["ts"].(float64)
		title := fmt.Sprintf("%v", m["title"])
		content := fmt.Sprintf("%v", m["content"])
		maxKey++
		memos[maxKey] = Memo{Title: title, Text: content, File: map[string]string{}, Time: int64(tsf)}
		added = append(added, maxKey)
	}
	memosMu.Unlock()
	if err := saveMemos(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 500, "message": "save fail"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": 200, "num": len(rdata), "data": rdata, "sync_id": added})
}

func OAuthCallbackHandler(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": 401, "message": "code not found"})
		return
	}

	// 有问题直接丢掉-v-
	if c.Query("error") != "" {
		c.Redirect(302, "/")
		return
	}

	// TODO: implement OAuth callback logic
	// 不对劲, 直接丢掉-v-
	if c.Query("state") != "note2026" {
		c.Redirect(302, "/")
		return
	}

	// 获取用户数据
	req := map[string]any{
		"grant_type": "code",
		"code":       code,
	}

	var res struct {
		Code uint8 `json:"code"`
		Data struct {
			Uid     int    `json:"uid"`
			Access  string `json:"access_token"`
			Refresh string `json:"refresh_token"`
			Expire  uint16 `json:"expires_in"`
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
		c.JSON(http.StatusBadRequest, gin.H{"status": 401, "message": "Can't gain verity!"})
		return

	}
	if res.Code != 0 {
		c.JSON(http.StatusBadRequest, gin.H{"status": 401, "message": "Code not match"})
		return
	}

	AE := time.Now().Add(time.Duration(res.Data.Expire) * time.Second)

	// 信息
	var info struct {
		Code uint8 `json:"code"`
		Data struct {
			Id   int    `json:"id"`
			Name string `json:"name"`
			Mail string `json:"mail"`
		} `json:"data"`
	}

	err = requests.
		URL("/api/profile/"+strconv.Itoa(res.Data.Uid)).
		Host("auth.overpass.top").
		Header("Authorization", `Bearer `+res.Data.Access).
		ToJSON(&info).
		Fetch(con)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 401, "message": "Can't get info!"})
		return

	}
	if res.Code != 0 {
		c.JSON(http.StatusBadRequest, gin.H{"status": 401, "message": "Access not match"})
		return
	}

	key := genKey(16)
	oauthMu.Lock()
	oauthKey[key] = UserInfo{
		Id:           uint32(info.Data.Id),
		Name:         info.Data.Name,
		Mail:         info.Data.Mail,
		AccessToken:  res.Data.Access,
		AccessExpire: AE,
		RefreshToken: res.Data.Refresh,
	}

	// 我开心就好-v-
	c.HTML(200, "back.htm", gin.H{
		"Key": key,
	})
}

func UserInfoHandler(c *gin.Context) {
	key := c.GetHeader("X-Key")
	if key == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "key is empty"})
		return
	}
	ok, msg := checkOAKey(key)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": msg})
		return
	}

	oauthMu.RLock()
	c.JSON(200, gin.H{
		"code": 0,
		"name": oauthKey[key].Name,
		"mail": oauthKey[key].Mail,
		"id":   oauthKey[key].Id,
	})
	oauthMu.RUnlock()
}
