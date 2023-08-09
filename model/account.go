package model

type Account struct {
	ID        uint64 `gorm:"column:id;not null;comment:主键ID;AUTO_INCREMENT;type:bigint(20)" json:"id"`
	Account   string `gorm:"column:account;default:NULL;comment:账户名;type:varchar(150)" json:"account"`
	Password  string `gorm:"column:password;default:NULL;comment:账户密码;type:varchar(150)" json:"password"`
	ChannelId uint64 `gorm:"column:channel_id;default:0;comment:渠道ID;type:bigint(20)" json:"channel_id"`
}

func GetAccount(channelId int) (info Account) {
	DB.Where("channel_id = ?", channelId).First(&info)
	return
}
