package common

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// 普通消息
func DingTalkGeneralMessage(content string) {
	robot := "general_message"
	atMobiles := strings.Split(os.Getenv(fmt.Sprintf("DING_ROBOT_%s_AT_MOBILE", strings.ToUpper(robot))), ",")
	_ = NewDingTalk(robot).Send(DingTextRequest{
		Msgtype: DingMsgTypeText,
		Text: struct {
			Content string `json:"content"`
		}{
			Content: fmt.Sprintf("【%s】新消息：", time.Now().Format(LayoutFull)) + content,
		},
		At: struct {
			AtMobiles []string `json:"atMobiles"`
			AtUserIds []string `json:"atUserIds"`
			IsAtAll   bool     `json:"isAtAll"`
		}{AtMobiles: atMobiles},
	})
}
