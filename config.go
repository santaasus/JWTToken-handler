package jwttokenhandler

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

const (
	Refresh = "refresh"
	Access  = "access"
)

type TokenClaims struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
	jwt.RegisteredClaims
}

// AppToken is a struct that contains the JWT token
type AppToken struct {
	Token          string    `json:"token"`
	TokenType      string    `json:"type"`
	ExpirationTime time.Time `json:"expitationTime"`
}

// TokenTypeKeyName is a map that contains the key name of the JWT in config.json
var TokenTypeKeyName = map[string]string{
	Access:  "Secure.JWTAccessSecure",
	Refresh: "Secure.JWTRefreshSecure",
}

// Structure likes in config.json
type SecureConfig struct {
	JWTAcessSecure     string `json:"JWTAcessSecure"`
	JWTRefreshSecure   string `json:"JWTRefreshSecure"`
	JWTAcessTimeMinute int    `json:"JWTAcessTimeMinute"`
	JWTRefreshTimeHour int    `json:"JWTRefreshTimeHour"`
}
