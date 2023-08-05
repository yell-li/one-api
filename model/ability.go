package model

import (
	"context"
	"fmt"
	"one-api/common"
	"strings"
	"sync"
	"time"
)

type Ability struct {
	Id           uint64 `json:"id"`
	Group        string `json:"group" gorm:"type:varchar(32);"`
	Model        string `json:"model" gorm:"type:varchar(200);"`
	ChannelId    int    `json:"channel_id" gorm:"index"`
	Enabled      bool   `json:"enabled"`
	SelectedTime int64  `json:"selected_time" gorm:"default:0"`
}

var randomSatisfiedSyncLock sync.RWMutex

func GetRandomSatisfiedChannel(group string, model string) (channel *Channel, err error) {
	var ability Ability
	channel = &Channel{}

	randomSatisfiedSyncLock.Lock() //加锁
	cacheKey := fmt.Sprintf("get_random_satisfied_ability_%s_%s", group, model)
	cacheAbilityId, _ := common.RDB.Get(context.Background(), cacheKey).Uint64()

	query := DB.Where("`group` = ? and model = ? and enabled = 1", group, model)
	if cacheAbilityId > 0 {
		query = query.Where("id != ?", cacheAbilityId)
	}
	err = query.Order("selected_time ASC").Limit(1).First(&ability).Error
	if ability.ChannelId <= 0 {
		randomSatisfiedSyncLock.Unlock() //解锁
		return
	}
	common.RDB.Set(context.Background(), cacheKey, ability.Id, 1*time.Minute)
	_ = DB.Model(Ability{}).Where("id = ?", ability.Id).Updates(map[string]interface{}{"selected_time": time.Now().UnixMilli()}).Error
	randomSatisfiedSyncLock.Unlock() //解锁

	channel.Id = ability.ChannelId
	err = DB.First(&channel, "id = ?", ability.ChannelId).Error
	return
}

func (channel *Channel) AddAbilities() error {
	models_ := strings.Split(channel.Models, ",")
	groups_ := strings.Split(channel.Group, ",")
	abilities := make([]Ability, 0, len(models_))
	for _, model := range models_ {
		for _, group := range groups_ {
			ability := Ability{
				Group:     group,
				Model:     model,
				ChannelId: channel.Id,
				Enabled:   channel.Status == common.ChannelStatusEnabled,
			}
			abilities = append(abilities, ability)
		}
	}
	return DB.Create(&abilities).Error
}

func (channel *Channel) DeleteAbilities() error {
	return DB.Where("channel_id = ?", channel.Id).Delete(&Ability{}).Error
}

// UpdateAbilities updates abilities of this channel.
// Make sure the channel is completed before calling this function.
func (channel *Channel) UpdateAbilities() error {
	// A quick and dirty way to update abilities
	// First delete all abilities of this channel
	err := channel.DeleteAbilities()
	if err != nil {
		return err
	}
	// Then add new abilities
	err = channel.AddAbilities()
	if err != nil {
		return err
	}
	return nil
}

func UpdateAbilityStatus(channelId int, status bool) error {
	return DB.Model(&Ability{}).Where("channel_id = ?", channelId).Select("enabled").Update("enabled", status).Error
}
