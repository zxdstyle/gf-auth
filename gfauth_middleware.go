package gfauth

import (
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
		a.failedResp(r)
		return
	}
	r.Middleware.Next()
}

func (a *Auth) doAuthenticate(r *ghttp.Request) error {
	if a.isExcludePaths(r.Request.URL) {
		return nil
	}

	t := a.option.TokenResolver(r)
	if len(t) == 0 {
		return ErrMissingToken
	}

	t = gstr.TrimLeftStr(t, "bearer")
	t = gstr.TrimLeftStr(t, "Bearer")
	t = gstr.TrimLeftStr(t, " ")
	identifier, payload, err := a.option.Generator.Decrypt(a.option.Secret, t)
	if err != nil {
		return err
	}

	r.SetCtxVar(contextIdentifierKey, identifier)
	r.SetCtxVar(contextClaimsKey, payload)

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

func (a *Auth) failedResp(r *ghttp.Request) {
	r.Response.WriteJson(g.Map{
		"code": 0,
		"msg":  http.StatusText(http.StatusUnauthorized),
	})
	r.Response.WriteHeader(http.StatusUnauthorized)
}
