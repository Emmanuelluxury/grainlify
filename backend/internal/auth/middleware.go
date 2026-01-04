package auth

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

const (
	LocalUserID = "user_id"
	LocalRole   = "role"
)

func RequireAuth(jwtSecret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		h := strings.TrimSpace(c.Get("Authorization"))
		if h == "" || !strings.HasPrefix(strings.ToLower(h), "bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing_bearer_token",
			})
		}
		token := strings.TrimSpace(h[len("bearer "):])
		claims, err := ParseJWT(jwtSecret, token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid_token",
			})
		}

		c.Locals(LocalUserID, claims.Subject)
		c.Locals(LocalRole, claims.Role)
		return c.Next()
	}
}

func RequireRole(roles ...string) fiber.Handler {
	allowed := map[string]struct{}{}
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(c *fiber.Ctx) error {
		role, _ := c.Locals(LocalRole).(string)
		if role == "" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "missing_role",
			})
		}
		if _, ok := allowed[role]; !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "insufficient_role",
			})
		}
		return c.Next()
	}
}









