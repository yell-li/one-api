package model

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-redis/redis/v8"
	"math/rand"
	"one-api/common"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	TokenCacheSeconds         = common.SyncFrequency
	UserId2GroupCacheSeconds  = common.SyncFrequency
	UserId2QuotaCacheSeconds  = common.SyncFrequency
	UserId2StatusCacheSeconds = common.SyncFrequency
)

func CacheGetTokenByKey(key string) (*Token, error) {
	var token Token
	if !common.RedisEnabled {
		err := DB.Where("`key` = ?", key).First(&token).Error
		return &token, err
	}
	tokenObjectString, err := common.RedisGet(fmt.Sprintf("token:%s", key))
	if err != nil {
		err := DB.Where("`key` = ?", key).First(&token).Error
		if err != nil {
			return nil, err
		}
		jsonBytes, err := json.Marshal(token)
		if err != nil {
			return nil, err
		}
		err = common.RedisSet(fmt.Sprintf("token:%s", key), string(jsonBytes), time.Duration(TokenCacheSeconds)*time.Second)
		if err != nil {
			common.SysError("Redis set token error: " + err.Error())
		}
		return &token, nil
	}
	err = json.Unmarshal([]byte(tokenObjectString), &token)
	return &token, err
}

func CacheGetUserGroup(id int) (group string, err error) {
	if !common.RedisEnabled {
		return GetUserGroup(id)
	}
	group, err = common.RedisGet(fmt.Sprintf("user_group:%d", id))
	if err != nil {
		group, err = GetUserGroup(id)
		if err != nil {
			return "", err
		}
		err = common.RedisSet(fmt.Sprintf("user_group:%d", id), group, time.Duration(UserId2GroupCacheSeconds)*time.Second)
		if err != nil {
			common.SysError("Redis set user group error: " + err.Error())
		}
	}
	return group, err
}

func CacheGetUserQuota(id int) (quota int, err error) {
	if !common.RedisEnabled {
		return GetUserQuota(id)
	}
	quotaString, err := common.RedisGet(fmt.Sprintf("user_quota:%d", id))
	if err != nil {
		quota, err = GetUserQuota(id)
		if err != nil {
			return 0, err
		}
		err = common.RedisSet(fmt.Sprintf("user_quota:%d", id), fmt.Sprintf("%d", quota), time.Duration(UserId2QuotaCacheSeconds)*time.Second)
		if err != nil {
			common.SysError("Redis set user quota error: " + err.Error())
		}
		return quota, err
	}
	quota, err = strconv.Atoi(quotaString)
	return quota, err
}

func CacheUpdateUserQuota(id int) error {
	if !common.RedisEnabled {
		return nil
	}
	quota, err := GetUserQuota(id)
	if err != nil {
		return err
	}
	err = common.RedisSet(fmt.Sprintf("user_quota:%d", id), fmt.Sprintf("%d", quota), time.Duration(UserId2QuotaCacheSeconds)*time.Second)
	return err
}

func CacheIsUserEnabled(userId int) bool {
	if !common.RedisEnabled {
		return IsUserEnabled(userId)
	}
	enabled, err := common.RedisGet(fmt.Sprintf("user_enabled:%d", userId))
	if err != nil {
		status := common.UserStatusDisabled
		if IsUserEnabled(userId) {
			status = common.UserStatusEnabled
		}
		enabled = fmt.Sprintf("%d", status)
		err = common.RedisSet(fmt.Sprintf("user_enabled:%d", userId), enabled, time.Duration(UserId2StatusCacheSeconds)*time.Second)
		if err != nil {
			common.SysError("Redis set user enabled error: " + err.Error())
		}
	}
	return enabled == "1"
}

var group2model2channels map[string]map[string][]*Channel
var channelSyncLock sync.RWMutex

func InitChannelCache() {
	newChannelId2channel := make(map[int]*Channel)
	var channels []*Channel
	DB.Where("status = ?", common.ChannelStatusEnabled).Find(&channels)
	for _, channel := range channels {
		newChannelId2channel[channel.Id] = channel
	}
	var abilities []*Ability
	DB.Find(&abilities)
	groups := make(map[string]bool)
	for _, ability := range abilities {
		groups[ability.Group] = true
	}
	newGroup2model2channels := make(map[string]map[string][]*Channel)
	for group := range groups {
		newGroup2model2channels[group] = make(map[string][]*Channel)
	}
	for _, channel := range channels {
		groups := strings.Split(channel.Group, ",")
		for _, group := range groups {
			models := strings.Split(channel.Models, ",")
			for _, model := range models {
				if _, ok := newGroup2model2channels[group][model]; !ok {
					newGroup2model2channels[group][model] = make([]*Channel, 0)
				}
				newGroup2model2channels[group][model] = append(newGroup2model2channels[group][model], channel)
			}
		}
	}
	channelSyncLock.Lock()
	group2model2channels = newGroup2model2channels
	channelSyncLock.Unlock()
	common.SysLog("channels synced from database")
}

func SyncChannelCache(frequency int) {
	for {
		time.Sleep(time.Duration(frequency) * time.Second)
		common.SysLog("syncing channels from database")
		InitChannelCache()
	}
}

func CacheGetRandomSatisfiedChannel(group string, model string) (*Channel, error) {
	if !common.RedisEnabled {
		return GetRandomSatisfiedChannel(group, model)
	}
	channelSyncLock.RLock()
	defer channelSyncLock.RUnlock()
	channels := group2model2channels[group][model]
	if len(channels) == 0 {
		return nil, errors.New("channel not found")
	}
	idx := rand.Intn(len(channels))
	return channels[idx], nil
}

func NewCacheGetRandomSatisfiedChannel(group string, model string) (*Channel, error) {
	channel := &Channel{}
	if !common.RedisEnabled {
		return GetRandomSatisfiedChannel(group, model)
	}
	channelIds := common.RDB.ZRange(context.Background(), getChannelGroupModelCacheKey(group, model), 0, 0).Val()
	if len(channelIds) <= 0 {
		return nil, errors.New("channel not inited")
	}
	common.RDB.ZAddXX(context.Background(), getChannelGroupModelCacheKey(group, model), &redis.Z{
		Score:  float64(time.Now().UnixMilli()),
		Member: channelIds[0],
	})
	cache := common.RDB.HGet(context.Background(), getChannelCacheKey(), channelIds[0]).Val()
	err := json.Unmarshal([]byte(cache), channel)
	return channel, err
}

func SyncChannelRDBCache(frequency int) {
	for {
		time.Sleep(time.Duration(frequency) * time.Second)
		common.SysLog("syncing channels from database")
		InitChannelRDBCache()
	}
}

func InitChannelRDBCache() {
	var channels []*Channel
	DB.Find(&channels)
	if len(channels) <= 0 {
		return
	}

	for _, channel := range channels {
		byt, _ := json.Marshal(channel)
		common.RDB.HSet(context.Background(), getChannelCacheKey(), channel.Id, string(byt))

		groups := strings.Split(channel.Group, ",")
		models := strings.Split(channel.Models, ",")
		for _, group := range groups {
			for _, model := range models {
				if channel.Status == common.ChannelStatusEnabled {
					common.RDB.ZAddNX(context.Background(), getChannelGroupModelCacheKey(group, model), &redis.Z{
						Score:  float64(time.Now().UnixMilli()),
						Member: channel.Id,
					})
				} else {
					common.RDB.ZRem(context.Background(), getChannelGroupModelCacheKey(group, model), channel.Id)
				}
			}
		}
	}
}

func getChannelCacheKey() string {
	return "all_channel_cache_data"
}

func getChannelGroupModelCacheKey(group string, model string) string {
	return fmt.Sprintf("channel_group_model_%s_%s", group, model)
}
