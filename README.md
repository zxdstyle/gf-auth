# 鉴权

## 鉴权中间件
推荐使用中间件的方式进行鉴权，以下实例中除了`/api/system`接口都会被中间件拦截鉴权：
```go
    s := g.Server()

    auth := gfauth.New(
		[]byte("secret"), 
		gfauth.WithExcludePaths("/api/system"),
    )

    s.Group("/api", func(api *ghttp.RouterGroup) {
        auth.AuthenticateMiddleware(api)
        api.GET("users", func(r *ghttp.Request) {
            r.Response.WriteJson(gtoken.Succ("system user"))
        })
        api.Bind(controller.Admin)
    }

    s.Run()
```

## 自定义鉴权中间件
如果需要进一步自定义逻辑，可以在自己的中间件或者其他任何地方调用`Check(r *ghttp.Request) error`方法：
```go
    s := g.Server()

    auth := gfauth.New(
		[]byte("secret"), 
		gfauth.WithExcludePaths("/api/system"),
    )

    s.Group("/api", func(api *ghttp.RouterGroup) {
        v1.Middleware(func(r *ghttp.Request) {
            if err := auth.Check(r); err != nil {
                r.Response.Write(err.Error())
                return
            }
            r.Middleware.Next()
        })
		
        api.GET("users", func(r *ghttp.Request) {
            r.Response.WriteJson(gtoken.Succ("system user"))
        })
        api.Bind(controller.Admin)
    }

    s.Run()
```
