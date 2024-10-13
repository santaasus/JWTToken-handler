package jwttokenhandler

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	domainErrors "github.com/santaasus/errors-handler"
)

func GenerateJWTToken(userID int, tokenType string) (appToken *AppToken, err error) {
	data, err := os.ReadFile(AbsPath("jwt_config.json"))

	if err != nil {
		fmt.Print(err)
		return
	}

	var config SecureConfig

	err = json.Unmarshal(data, &config)
	if err != nil {
		return
	}

	JWTSecureKey := config.JWTAcessSecure
	JWTExpTime := config.JWTAcessTimeMinute

	if tokenType == Refresh {
		JWTSecureKey = config.JWTRefreshSecure
		JWTExpTime = config.JWTRefreshTimeHour
	}

	tokenTime, err := strconv.ParseInt(strconv.Itoa(JWTExpTime), 10, 64)
	if err != nil {
		return
	}

	tokenTimeUnix := time.Duration(tokenTime)
	switch tokenType {
	case Access:
		tokenTimeUnix *= time.Hour * 10
	case Refresh:
		tokenTimeUnix *= time.Hour * 36
	default:
		err = errors.New("invalid token type")
	}

	if err != nil {
		return
	}

	tokenExpirationTime := time.Now().Add(tokenTimeUnix)

	claims := &TokenClaims{
		ID:   userID,
		Type: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(tokenExpirationTime),
		},
	}
	tokenWithNewClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenStr, err := tokenWithNewClaims.SignedString([]byte(JWTSecureKey))
	if err != nil {
		return
	}

	appToken = &AppToken{
		Token:          tokenStr,
		TokenType:      tokenType,
		ExpirationTime: tokenExpirationTime,
	}

	return
}

func VerifyTokenAndGetClaims(token, tokenType string) (claims jwt.MapClaims, err error) {
	data, err := os.ReadFile(AbsPath("jwt_config.json"))

	if err != nil {
		_ = fmt.Errorf("fatal error in config file: %s", err.Error())
		return
	}

	var config SecureConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return
	}

	JWTRefreshSecureKey := config.JWTAcessSecure
	if tokenType != Access {
		JWTRefreshSecureKey = config.JWTRefreshSecure
	}

	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			errorString := fmt.Sprintf("wrong signing method %v", t.Header["alg"])
			return nil, &domainErrors.AppError{
				Err:  errors.New(errorString),
				Type: domainErrors.NotAuthenticated,
			}
		}

		return []byte(JWTRefreshSecureKey), nil
	})

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		if claims["type"] != tokenType {
			return nil, &domainErrors.AppError{
				Err:  errors.New("invalid token type"),
				Type: domainErrors.NotAuthenticated,
			}
		}

		var expTime = claims["exp"].(float64)
		if time.Now().Unix() > int64(expTime) {
			return nil, &domainErrors.AppError{
				Err:  errors.New("token expired"),
				Type: domainErrors.NotAuthenticated,
			}
		}

		return claims, nil
	}

	return
}
