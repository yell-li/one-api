package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"io"
	"net/http"
	url2 "net/url"
	"os"
	"strings"
	"time"
)

type ChatGptService struct {
	authHost      string
	proxyURL      string
	email         string
	password      string
	userAgent     string
	clientId      string
	codeChallenge string
	codeVerifier  string
}

// 获取账户余额信息
func (c *ChatGptService) GetCredit(email, password string) (credit OpenApiCreditSummary, err error) {
	accessToken := c.GetCacheAccessToken(email, password)
	if accessToken == "" {
		err = errors.New("获取accessToken失败")
		return
	}
	c.proxyURL = os.Getenv("OPENAI_PROXY")
	if c.proxyURL == "" {
		c.proxyURL = "https://api.openai.com"
	}
	login := c.proxyURL + "/dashboard/onboarding/login"
	resp, err := resty.New().R().SetHeaders(map[string]string{"Authorization": fmt.Sprintf("Bearer %s", accessToken)}).Post(login)
	if err != nil {
		return
	}
	var loginResponse OpenApiLoginResponse
	err = json.Unmarshal(resp.Body(), &loginResponse)
	if err != nil {
		return
	}
	if loginResponse.User.Session.SensitiveId == "" {
		err = errors.New("获取 Session id 失败")
		return
	}

	url := c.proxyURL + "/dashboard/billing/credit_grants"
	resp, err = resty.New().R().SetHeaders(map[string]string{"Authorization": fmt.Sprintf("Bearer %s", loginResponse.User.Session.SensitiveId)}).Get(url)
	if err != nil {
		return
	}
	err = json.Unmarshal(resp.Body(), &credit)
	return
}

// 获取缓存ChatGPT token
func (c *ChatGptService) GetCacheAccessToken(email string, password string) string {
	cacheKey := fmt.Sprintf("get_chat_gpt_cache_access_token_%s_%s", email, password)
	cache := RDB.Get(context.Background(), cacheKey).Val()
	if cache != "" {
		return cache
	}
	auth, err := c.GetAuthToken(email, password)
	if err != nil {
		DingTalkGeneralMessage(fmt.Sprintf("获取ChatGpttoken信息失败,acount:%s, error:%s", email, err.Error()))
	}

	expire := 48 * time.Hour
	if differ := auth.ExpiresIn - 7200; auth.ExpiresIn < time.Now().Unix() && differ > 0 {
		expire = time.Duration(differ) * time.Second
	}
	RDB.Set(context.Background(), cacheKey, auth.AccessToken, expire)
	return auth.AccessToken
}

// 获取AccessToken，Python实现获取token相关代码：https://github.com/pengzhile/pandora/blob/v1.3.0/src/pandora/openai/auth.py
func (c *ChatGptService) GetAuthToken(email string, password string) (auth AuthData, err error) {
	//1，初始化基础数据
	c.initAuth(email, password)
	//2.获取预登陆cookie和state
	cookies, state, err := c.getPreLoginCookieAndState()
	if err != nil {
		return
	}

	//3.发送预登陆数据
	err = c.sendPreLoginData(state, cookies)
	if err != nil {
		return
	}

	//4.发送登陆数据
	location, referer, err := c.sendLoginData(state, cookies)
	if err != nil {
		return
	}

	//5.oauth认证跳转
	redirectAuthLocation, err := c.getAuthCode(location, referer, cookies)
	if err != nil {
		return
	}

	//6.获取登录认证数据
	auth, err = c.getAuthData(redirectAuthLocation, cookies)
	return
}

func (c *ChatGptService) initAuth(email string, password string) {
	c.authHost = "https://auth0.openai.com"

	c.proxyURL = os.Getenv("OPENAI_PROXY")
	if c.proxyURL == "" {
		c.proxyURL = c.authHost
	}
	c.email = email
	c.password = password
	c.userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
	c.codeChallenge = "w6n3Ix420Xhhu-Q5-mOOEyuPZmAsJHUbBpO8Ub7xBCY"
	c.codeVerifier = "yGrXROHx_VazA0uovsxKfE263LMFcrSrdm4SlC-rob8"
	c.clientId = "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh"
}

func (c *ChatGptService) getPreAuthCookie() (cookie AuthCookie, err error) {
	url := "https://ai.fakeopen.com/auth/preauth"
	resp, err := resty.New().R().Get(url)
	if err != nil {
		return
	}
	_ = json.Unmarshal(resp.Body(), &cookie)
	return
}

func (c *ChatGptService) getPreLoginCookieAndState() (cookies []*http.Cookie, state string, err error) {
	preAuthCookie, err := c.getPreAuthCookie()
	if err != nil {
		return
	}

	url := c.proxyURL + "/authorize?client_id=" + c.clientId + "&audience=https%3A%2F%2Fapi.openai.com%2Fv1&redirect_uri=com.openai.chat%3A%2F%2Fauth0.openai.com%2Fios%2Fcom.openai.chat%2Fcallback&scope=openid%20email%20profile%20offline_access%20model.request%20model.read%20organization.read%20offline&response_type=code&preauth_cookie=" + preAuthCookie.PreAuthCookie + "&code_challenge=" + c.codeChallenge + "&code_challenge_method=S256&prompt=login"

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar:     nil,
		Timeout: 30 * time.Second,
	}

	req := &http.Request{
		Header: http.Header{
			"User-Agent": []string{c.userAgent},
			"Referer":    []string{"https://ios.chat.openai.com/"},
		},
	}
	req.URL, _ = url2.Parse(url)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode == 302 {
		cookies = resp.Cookies()
		urlObj, er := url2.Parse(resp.Header.Get("Location"))
		if er != nil {
			err = errors.New("获取跳转Location地址失败")
			return
		}
		params, er := url2.ParseQuery(urlObj.RawQuery)
		if er != nil {
			err = errors.New("解析跳转Location地址参数失败")
			return
		}
		state = params.Get("state")
	}
	return
}

func (c *ChatGptService) sendPreLoginData(state string, cookies []*http.Cookie) (err error) {
	path := "/u/login/identifier?state=" + state
	data := url2.Values{
		"state":                       []string{state},
		"username":                    []string{c.email},
		"js-available":                []string{"true"},
		"webauthn-available":          []string{"true"},
		"is-brave":                    []string{"false"},
		"webauthn-platform-available": []string{"false"},
		"action":                      []string{"default"},
	}
	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar:     nil,
		Timeout: 30 * time.Second,
	}
	req := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"content-type": []string{"application/x-www-form-urlencoded"},
			"User-Agent":   []string{c.userAgent},
			"Referer":      []string{c.authHost + path},
			"Origin":       []string{c.authHost},
		},
		Body: io.NopCloser(strings.NewReader(data.Encode())),
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	req.URL, _ = url2.Parse(c.proxyURL + path)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode == 302 || resp.StatusCode == 200 {
		return
	}
	return errors.New(fmt.Sprintf("发送预登录数据失败：StatusCode#%d", resp.StatusCode))
}

func (c *ChatGptService) sendLoginData(state string, cookies []*http.Cookie) (location, referer string, err error) {
	path := "/u/login/password?state=" + state
	url := c.proxyURL + path

	data := url2.Values{
		"state":    []string{state},
		"username": []string{c.email},
		"password": []string{c.password},
		"action":   []string{"default"},
	}
	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar:     nil,
		Timeout: 30 * time.Second,
	}
	req := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"Content-Type": []string{"application/x-www-form-urlencoded"},
			"User-Agent":   []string{c.userAgent},
			"Referer":      []string{c.authHost + path},
			"Origin":       []string{c.authHost},
		},
		Body: io.NopCloser(strings.NewReader(data.Encode())),
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	req.URL, _ = url2.Parse(url)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode == 302 || resp.StatusCode == 200 {
		location = resp.Header.Get("Location")
		return
	}
	err = errors.New(fmt.Sprintf("send login data error and response code is %d", resp.StatusCode))
	return
}

func (c *ChatGptService) getAuthCode(location, referer string, cookies []*http.Cookie) (authCode string, err error) {
	url := c.proxyURL + location

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar:     nil,
		Timeout: 30 * time.Second,
	}

	req := &http.Request{
		Header: http.Header{
			"User-Agent": []string{c.userAgent},
			"Referer":    []string{referer},
			"Origin":     []string{c.authHost},
		},
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	req.URL, _ = url2.Parse(url)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode == 302 || resp.StatusCode == 200 {
		redirectAuthLocation := resp.Header.Get("Location")
		urlObj, _ := url2.Parse(redirectAuthLocation)
		params, _ := url2.ParseQuery(urlObj.RawQuery)
		if params.Get("error") != "" {
			err = errors.New(params.Get("error_description"))
			return
		}
		authCode = params.Get("code")
		return
	}

	err = errors.New(fmt.Sprintf("get redirect auth location error, and response code is %d", resp.StatusCode))
	return
}

func (c *ChatGptService) getAuthData(authCode string, cookies []*http.Cookie) (auth AuthData, err error) {
	url := c.proxyURL + "/oauth/token"
	data := url2.Values{
		"redirect_uri":  []string{"com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback"},
		"grant_type":    []string{"authorization_code"},
		"client_id":     []string{c.clientId},
		"code":          []string{authCode},
		"code_verifier": []string{c.codeVerifier},
	}

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar:     nil,
		Timeout: 30 * time.Second,
	}
	req := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{
			"User-Agent":   []string{c.userAgent},
			"Content-Type": []string{"application/x-www-form-urlencoded"},
		},
		Body: io.NopCloser(strings.NewReader(data.Encode())),
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	req.URL, _ = url2.Parse(url)
	resp, err := client.Do(req)
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("get auth data error, and response code is %d", resp.StatusCode))
		return
	}
	byt, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal(byt, &auth)
	return
}

type AuthData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type AuthCookie struct {
	PreAuthCookie string `json:"preauth_cookie"`
}

type OpenApiLoginResponse struct {
	Object string `json:"object"`
	User   struct {
		Object  string        `json:"object"`
		Id      string        `json:"id"`
		Email   string        `json:"email"`
		Name    string        `json:"name"`
		Picture string        `json:"picture"`
		Created int           `json:"created"`
		Groups  []interface{} `json:"groups"`
		Session struct {
			SensitiveId string      `json:"sensitive_id"`
			Object      string      `json:"object"`
			Name        interface{} `json:"name"`
			Created     int         `json:"created"`
			LastUse     int         `json:"last_use"`
			Publishable bool        `json:"publishable"`
		} `json:"session"`
		Orgs struct {
			Object string `json:"object"`
			Data   []struct {
				Object      string        `json:"object"`
				Id          string        `json:"id"`
				Created     int           `json:"created"`
				Title       string        `json:"title"`
				Name        string        `json:"name"`
				Description string        `json:"description"`
				Personal    bool          `json:"personal"`
				IsDefault   bool          `json:"is_default"`
				Role        string        `json:"role"`
				Groups      []interface{} `json:"groups"`
			} `json:"data"`
		} `json:"orgs"`
		IntercomHash string        `json:"intercom_hash"`
		Amr          []interface{} `json:"amr"`
	} `json:"user"`
	Invites []interface{} `json:"invites"`
}

type OpenApiCreditSummary struct {
	Object         string  `json:"object"`
	TotalGranted   float64 `json:"total_granted"`
	TotalUsed      float64 `json:"total_used"`
	TotalAvailable float64 `json:"total_available"`
	Grants         struct {
		Object string `json:"object"`
		Data   []struct {
			Object      string  `json:"object"`
			Id          string  `json:"id"`
			GrantAmount float64 `json:"grant_amount"`
			UsedAmount  float64 `json:"used_amount"`
			EffectiveAt float64 `json:"effective_at"`
			ExpiresAt   float64 `json:"expires_at"`
		} `json:"data"`
	} `json:"grants"`
}
