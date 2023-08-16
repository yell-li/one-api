package common

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const DingMsgTypeText = "text"
const DingMsgTypeLink = "link"
const DingMsgTypeMarkdown = "markdown"
const DingMsgTypeSimpleActionCard = "actionCard"
const DingMsgTypeMultipleActionCard = "actionCard"

// text类型
type DingTextRequest struct {
	Msgtype string `json:"msgtype"`
	Text    struct {
		Content string `json:"content"`
	} `json:"text"`
	At struct {
		AtMobiles []string `json:"atMobiles"`
		AtUserIds []string `json:"atUserIds"`
		IsAtAll   bool     `json:"isAtAll"`
	} `json:"at"`
}

// link类型
type DingLinkRequest struct {
	Msgtype string `json:"msgtype"`
	Link    struct {
		Text       string `json:"text"`
		Title      string `json:"title"`
		PicURL     string `json:"picUrl"`
		MessageURL string `json:"messageUrl"`
	} `json:"link"`
}

// markdown类型
type DingMarkdownRequest struct {
	Msgtype  string `json:"msgtype"`
	Markdown struct {
		Title string `json:"title"`
		Text  string `json:"text"`
	} `json:"markdown"`
	At struct {
		AtMobiles []string `json:"atMobiles"`
		AtUserIds []string `json:"atUserIds"`
		IsAtAll   bool     `json:"isAtAll"`
	} `json:"at"`
}

// 整体跳转ActionCard类型：单个链接
type DingSimpleActionCardRequest struct {
	Msgtype    string `json:"msgtype"`
	ActionCard struct {
		Title          string `json:"title"`
		Text           string `json:"text"`
		BtnOrientation string `json:"btnOrientation"`
		SingleTitle    string `json:"singleTitle"`
		SingleURL      string `json:"singleURL"`
	} `json:"actionCard"`
}

// 独立跳转ActionCard类型：多个链接
type DingMultipleAutoGenerated struct {
	Msgtype    string `json:"msgtype"`
	ActionCard struct {
		Title          string `json:"title"`
		Text           string `json:"text"`
		BtnOrientation string `json:"btnOrientation"`
		Btns           []struct {
			Title     string `json:"title"`
			ActionURL string `json:"actionURL"`
		} `json:"btns"`
	} `json:"actionCard"`
}

type DingResponse struct {
	Errcode int    `json:"errcode"`
	Errmsg  string `json:"errmsg"`
}

type dingTalk struct {
	Url   string
	Robot string
	Token string
}

func NewDingTalk(robot string) *dingTalk {
	return &dingTalk{
		Url:   os.Getenv("DING_ROBOT_HOST") + "/robot/send?access_token=",
		Robot: robot,
		Token: os.Getenv(fmt.Sprintf("DING_ROBOT_%s_TOKEN", strings.ToUpper(robot))),
	}
}

// 调用Ding 接口
// 文档地址：https://developers.dingtalk.com/document/robots/custom-robot-access
func (d *dingTalk) Send(request interface{}) (err error) {
	//初始化检查
	err = d.initAndCheck()
	if err != nil {
		return
	}

	condition, _ := json.Marshal(request)
	resp, err := resty.New().R().SetHeader("Content-Type", "application/json").SetBody(string(condition)).Post(d.Url)
	if err != nil {
		return
	}
	if code := resp.StatusCode(); code != http.StatusOK {
		err = errors.New(fmt.Sprintf("DingTalk请求失败:%d", code))
		return
	}

	if resp == nil || len(resp.Body()) == 0 {
		err = errors.New("发送Ding消息失败")
		return
	}
	var data DingResponse
	err = json.Unmarshal(resp.Body(), &data)
	if err != nil {
		return
	}
	if data.Errcode != 0 {
		err = errors.New("Send DingTalk Msg Err: " + data.Errmsg)
	}
	return
}

// 初始化检查
func (d *dingTalk) initAndCheck() (err error) {
	if d.Token == "" {
		err = errors.New("不存在钉钉机器人:" + d.Robot + "未配置token")
		return
	}
	//拼接token
	d.Url += d.Token

	//拼接签名
	//if secret, ok := d.Config["secret"]; ok || secret != "" {
	//	timestamp, sign := d.sign(secret)
	//	d.Url += fmt.Sprintf("&timestamp=%d&sign=%s", timestamp, sign)
	//}

	return
}

// 签名认证
func (d *dingTalk) sign(secret string) (timestamp int64, sign string) {
	timestamp = time.Now().UnixNano() / 1e6
	str := fmt.Sprintf("%d\n%s", timestamp, secret)

	str = Sha256(str, secret)
	str = base64.StdEncoding.EncodeToString([]byte(str))

	sign = url.QueryEscape(str)
	return
}

// Sha256加密
func Sha256(text string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(text))

	return string(h.Sum(nil))
}
