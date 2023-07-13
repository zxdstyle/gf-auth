package gfauth

import (
	"net/url"
	"testing"
)

func TestIsExcludePaths(t *testing.T) {

	cases := []struct {
		name         string
		u            *url.URL
		excludePaths []string
		want         bool
	}{
		{name: "全路径匹配", u: &url.URL{Path: "/"}, excludePaths: []string{"/"}, want: true},
		{name: "全路径匹配", u: &url.URL{Path: ""}, excludePaths: []string{"/"}, want: true},
		{name: "全路径匹配", u: &url.URL{Path: "/api/v1/login"}, excludePaths: []string{"/api/v1/login"}, want: true},
		{name: "全路径匹配", u: &url.URL{Path: "/api/v1/login"}, excludePaths: []string{"/api/v1/logout"}, want: false},
		{name: "全路径匹配", u: &url.URL{Path: "/api/v1/login"}, excludePaths: []string{"/api/v1/logout", "/api/v1/login"}, want: true},
		{name: "模糊匹配", u: &url.URL{Path: "/"}, excludePaths: []string{"/*"}, want: true},
		{name: "模糊匹配", u: &url.URL{Path: "/api/v1/login"}, excludePaths: []string{"/*"}, want: true},
		{name: "模糊匹配", u: &url.URL{Path: "/api/v1/login"}, excludePaths: []string{"/api/*"}, want: true},
		{name: "模糊匹配", u: &url.URL{Path: "/api/v1/logout"}, excludePaths: []string{"/api/v1/*"}, want: true},
		{name: "模糊匹配", u: &url.URL{Path: "/"}, excludePaths: []string{"/api/v1/*"}, want: false},
		{name: "模糊匹配", u: &url.URL{Path: "/"}, excludePaths: []string{"/*"}, want: true},
		{name: "模糊匹配", u: &url.URL{Path: ""}, excludePaths: []string{"/api*"}, want: false},
		{name: "模糊匹配", u: &url.URL{Path: ""}, excludePaths: []string{"/*"}, want: true},
		{name: "模糊匹配", u: &url.URL{Path: ""}, excludePaths: []string{"*"}, want: false},
		{name: "模糊匹配", u: &url.URL{Path: "/api/v1/login"}, excludePaths: []string{"*"}, want: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			auth := New([]byte("test"), WithExcludePaths(c.excludePaths...))
			if res := auth.isExcludePaths(c.u); res != c.want {
				t.Errorf("unexpect result: %v, want: %v", res, c.want)
			}
		})
	}
}
