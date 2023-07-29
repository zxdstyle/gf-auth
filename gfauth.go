package gfauth

import (
	"context"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/util/gconv"
	"net/http"
)

type Auth struct {
	option *Option
}

func New(secret []byte, options ...OptionFunc) *Auth {
	opt := defaultOption()
	opt.Secret = secret
	for _, option := range options {
		option(opt)
	}

	return &Auth{
		option: opt,
	}
}

func (a *Auth) AuthenticateMiddleware(group *ghttp.RouterGroup) {
	group.Middleware(a.authenticateMiddleware)
}

func (a *Auth) CanMiddleware(group *ghttp.RouterGroup, abilities ...string) {
	group.Middleware(func(r *ghttp.Request) {
		if err := a.doCan(r, abilities...); err != nil {
			g.Log().Error(r.Context(), err)
			a.failedResp(r, http.StatusForbidden)
			return
		}
		r.Middleware.Next()
	})
}

func (a *Auth) Check(r *ghttp.Request) error {
	return a.doAuthenticate(r)
}

func (a *Auth) Token(user IUser) ([]byte, error) {
	return a.doGenerateToken(user)
}

func (a *Auth) TokenWithAbilities(user IUser, abilities ...string) ([]byte, error) {
	return a.doGenerateToken(user, abilities...)
}

func (a *Auth) doGenerateToken(user IUser, abilities ...string) ([]byte, error) {
	payload := make(map[string]interface{})
	payload["id"] = user.GetIdentifier()

	claims, ok := user.(IUserWithCustomClaims)
	if ok {
		payload["claims"] = claims.GetCustomClaims()
	}
	if len(abilities) > 0 {
		payload["abilities"] = abilities
	}

	return a.option.Generator.Encrypt(a.option.Secret, payload)
}

func GetIdentifierFromCtx(ctx context.Context) string {
	return gconv.String(g.RequestFromCtx(ctx).GetCtxVar(contextIdentifierKey))
}

func GetCustomClaimsFromCtx(ctx context.Context) map[string]interface{} {
	return gconv.Map(ctx.Value(contextClaimsKey))
}
