package gfauth

import (
	"context"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func init() {
	jwt.TimePrecision = time.Nanosecond
}

type (
	JwtGenerator struct {
		signingMethod jwt.SigningMethod
	}

	CustomClaims struct {
		jwt.RegisteredClaims
		Claims map[string]interface{}
	}
)

func NewHS256JWTGenerator() *JwtGenerator {
	return &JwtGenerator{
		signingMethod: jwt.SigningMethodHS256,
	}
}

func (t JwtGenerator) Encrypt(secret []byte, claims map[string]interface{}) ([]byte, error) {
	var (
		ctx      = context.Background()
		duration = g.Cfg().MustGet(ctx, "auth.expiration", 3600).Duration()
		payload  = CustomClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "gf-auth",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * duration)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
			},
			Claims: claims,
		}
		token = jwt.NewWithClaims(t.signingMethod, payload)
	)

	tokenStr, err := token.SignedString(secret)
	if err != nil {
		return nil, err
	}
	return []byte(tokenStr), nil
}

func (t JwtGenerator) Decrypt(secret []byte, tokenStr string) (string, map[string]interface{}, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if t.signingMethod != token.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		return secret, nil
	})
	if err != nil {
		return "", nil, err
	}
	var (
		claims = token.Claims.(jwt.MapClaims)
		custom = claims["Claims"].(map[string]interface{})
	)

	return gconv.String(custom["id"]), gconv.Map(custom["claims"]), nil
}
