package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

func DetectBot() fiber.Handler {
	blockedAgents := []string{"curl","python","wget","httpclient","go-http-client","scanner","bot","libwww"}

	return func(c *fiber.Ctx) error {
		ua := strings.ToLower(c.Get("User-Agent"))
		if ua == "" {
			return c.Status(403).JSON(fiber.Map{"error":"Forbidden","message":"User-Agent kosong"})
		}
		for _, b := range blockedAgents {
			if strings.Contains(ua, b) {
				return c.Status(403).JSON(fiber.Map{"error":"Forbidden","message":"User-Agent diblokir"})
			}
		}
		return c.Next()
	}
}
