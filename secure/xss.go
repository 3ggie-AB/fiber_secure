package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/microcosm-cc/bluemonday"
)

var strict = bluemonday.StrictPolicy()

func containsXSS(v interface{}) bool {
	switch val := v.(type) {
	case string:
		clean := strict.Sanitize(val)
		if clean != val {
			return true
		}
		bad := []string{"<script", "</script", "onerror=", "onclick=", "<img", "<iframe", "<svg", "javascript:"}
		lower := strings.ToLower(val)
		for _, b := range bad {
			if strings.Contains(lower, b) {
				return true
			}
		}
		return false
	case map[string]interface{}:
		for _, v2 := range val {
			if containsXSS(v2) {
				return true
			}
		}
		return false
	case []interface{}:
		for _, v2 := range val {
			if containsXSS(v2) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func RejectXSS() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if c.Method() != http.MethodPost && c.Method() != http.MethodPut && c.Method() != http.MethodPatch {
			return c.Next()
		}
		raw := c.Body()
		if len(raw) == 0 {
			return c.Next()
		}
		var body map[string]interface{}
		if err := json.Unmarshal(raw, &body); err != nil {
			return c.Next()
		}
		if containsXSS(body) {
			return c.Status(400).JSON(fiber.Map{
				"error":   "Bad Request",
				"message": "Input berbahaya terdeteksi. Request ditolak.",
			})
		}
		return c.Next()
	}
}
