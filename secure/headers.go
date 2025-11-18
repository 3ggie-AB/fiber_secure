package middleware

import (
	"github.com/gofiber/fiber/v2"
)

// SecurityHeaders pasang headers HTTP penting untuk proteksi
func SecurityHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Content Security Policy → batasi resource eksternal
		c.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self';")

		// XSS Protection → legacy tapi kadang masih dipakai
		c.Set("X-XSS-Protection", "1; mode=block")

		// Prevent MIME type sniffing
		c.Set("X-Content-Type-Options", "nosniff")

		// Clickjacking protection
		c.Set("X-Frame-Options", "DENY")

		// Referrer policy
		c.Set("Referrer-Policy", "no-referrer")

		// Strict Transport Security → HTTPS wajib
		c.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

		// Permissions policy → batasi fitur browser tertentu
		c.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		return c.Next()
	}
}
