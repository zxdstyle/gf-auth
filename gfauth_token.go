package gfauth

import "github.com/gogf/gf/v2/net/ghttp"

type (
	ITokenClaims interface {
		Identifier() string
		Payload() map[string]interface{}
		Abilities() []string
	}

	TokenGenerator interface {
		Encrypt(secret []byte, payload map[string]interface{}) ([]byte, error)
		Decrypt(secret []byte, tokenStr string) (ITokenClaims, error)
	}

	TokenResolver func(r *ghttp.Request) string
)

func ResolveTokenFromHeader(r *ghttp.Request) string {
	return r.Request.Header.Get("Authorization")
}
