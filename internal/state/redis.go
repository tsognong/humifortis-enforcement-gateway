package state

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/redis/go-redis/v9"
	"time"
)

type Redis struct {
	client *redis.Client
	prefix string
}

func NewRedis(url, prefix string) (*Redis, error) {
	options, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	if prefix == "" {
		prefix = "humifortis:gateway:"
	}
	return &Redis{client: redis.NewClient(options), prefix: prefix}, nil
}
func (r *Redis) key(value string) string { return r.prefix + value }
func (r *Redis) Get(ctx context.Context, key string) (*Constraint, error) {
	raw, err := r.client.Get(ctx, r.key("constraint:"+key)).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var value Constraint
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if time.Now().After(value.ExpiresAt) {
		return nil, nil
	}
	return &value, nil
}
func (r *Redis) Put(ctx context.Context, key string, value Constraint) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return r.client.Set(ctx, r.key("constraint:"+key), raw, time.Until(value.ExpiresAt)).Err()
}
func (r *Redis) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, r.key("constraint:"+key)).Err()
}
func (r *Redis) FirstUse(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return r.client.SetNX(ctx, r.key("replay:"+key), "1", ttl).Result()
}
func (r *Redis) Ping(ctx context.Context) error {
	if r == nil || r.client == nil {
		return fmt.Errorf("redis is not configured")
	}
	return r.client.Ping(ctx).Err()
}
