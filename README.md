

# uos-oauth2-client
111
功能：
uos-oauth2-client 包为用户返回一个gin engine。 
在实例化的engine中实现了与oauth2 server交互的相关功能，并提供了一个auth 中间件，用于对需要做认证的请求uri 做认证管理
这里仅支持验证码模式（authorization code）的 oauth2协议
使用：

go get githut.com/fsp1yjl/auth2engine


```bigquery

// 加载配置
authConfig := loadOAuthConfig()
// 基于配置初始化oauth2 app engine
eng := auth2engine.InitEngine(authConfig)

// 基于oauth2 app engine 设置自己的应用route group 并对这个route group增加 auth中间件
appGroup:= eng.Group("app").Use(auth2engine.AuthMiddlewarer())

// 在自定义route group中实现自己app的应用逻辑
```

demo :
参见: demo/demoapp.go


```go
// go doc 
func AuthMiddlewarer() gin.HandlerFunc // 返回一个进行认证处理的中间件
func InitEngine(conf *AuthEngineConfig) *gin.Engine // 初始化一个包含oauth gin web engine
func TokenCheck(sess sessions.Session) bool  // 判断session中是否包含合法token信息
type AuthEngineConfig struct{ ... } // oauth app engine 配置
type OAuth2Config struct{ ... } // oauth2 服务器配置信息
type RedisConf struct{ ... }  //redis session store 结构体
type UserInfo struct{ ... } // oauth token对应的用户细心
    func GetUserInfo(c *gin.Context) (info UserInfo, err error)

```
