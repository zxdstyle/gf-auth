package gfauth

import (
	"github.com/gogf/gf/v2/container/garray"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/text/gstr"
	"net/http"
	"net/url"
	"strings"
)

type contextKey string

var (
	contextIdentifierKey = contextKey("id")
	contextClaimsKey     = contextKey("claims")
)

func (a *Auth) authenticateMiddleware(r *ghttp.Request) {
	if err := a.doAuthenticate(r); err != nil {
		g.Log().Error(r.Context(), err)
		a.failedResp(r, http.StatusUnauthorized)
		return
	}
	r.Middleware.Next()
}

func (a *Auth) doAuthenticate(r *ghttp.Request) error {
	if a.isExcludePaths(r.Request.URL) {
		return nil
	}

	claims, err := a.resolveToken(r)
	if err != nil {
		return err
	}

	r.SetCtxVar(contextIdentifierKey, claims.Identifier())
	r.SetCtxVar(contextClaimsKey, claims.Payload())

	return nil
}

func (a *Auth) doCan(r *ghttp.Request, abilities ...string) error {
	if len(abilities) == 0 {
		return nil
	}

	t := a.option.TokenResolver(r)
	if len(t) == 0 {
		return ErrMissingToken
	}

	claims, err := a.resolveToken(r)
	if err != nil {
		return err
	}

	abs := garray.NewStrArrayFrom(claims.Abilities())
	if len(abilities) == 1 {
		if abs.Contains(abilities[0]) {
			return nil
		}
		return ErrForbiddenAbility
	}

	for _, ability := range abilities {
		if !abs.Contains(ability) {
			return ErrForbiddenAbility
		}
	}

	return nil
}

// isExcludePaths Whether the request url is in the excluded paths
func (a *Auth) isExcludePaths(u *url.URL) bool {
	if a.option.ExcludePaths == nil || len(a.option.ExcludePaths) == 0 {
		return false
	}

	path := strings.TrimRight(u.Path, "/")
	for _, excludePath := range a.option.ExcludePaths {
		tmpPath := strings.TrimRight(excludePath, "/")
		// 前缀匹配
		if strings.HasSuffix(tmpPath, "/*") {
			tmpPath = strings.TrimRight(tmpPath, "/*")
			if strings.HasPrefix(path, tmpPath) {
				return true
			}
		}

		if path == tmpPath {
			return true
		}
	}
	return false
}

func (a *Auth) resolveToken(r *ghttp.Request) (claims ITokenClaims, err error) {
	t := a.option.TokenResolver(r)
	if len(t) == 0 {
		err = ErrMissingToken
		return
	}

	t = gstr.TrimLeftStr(t, "bearer")
	t = gstr.TrimLeftStr(t, "Bearer")
	t = gstr.TrimLeftStr(t, " ")

	return a.option.Generator.Decrypt(a.option.Secret, t)
}

func (a *Auth) failedResp(r *ghttp.Request, code int) {
	r.Response.WriteJson(g.Map{
		"code": 0,
		"msg":  http.StatusText(code),
	})
	r.Response.WriteHeader(code)
}
