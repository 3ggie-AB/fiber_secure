package middleware

import (
    "sync"
    "time"
    "github.com/gofiber/fiber/v2"
    "golang.org/x/time/rate"
)

var (
    defaultLimiters = make(map[string]*rate.Limiter)
    mu sync.Mutex
)

func DefaultRateLimit(rps float64, burst int) fiber.Handler {
    return func(c *fiber.Ctx) error {
        ip := c.IP()

        mu.Lock()
        limiter, exists := defaultLimiters[ip]
        if !exists {
            limiter = rate.NewLimiter(rate.Limit(rps), burst)
            defaultLimiters[ip] = limiter
        }
        mu.Unlock()

        if !limiter.Allow() {
            return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
                "error": "too many requests",
            })
        }

        return c.Next()
    }
}
