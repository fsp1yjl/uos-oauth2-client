package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	auth2engine "githut.com/fsp1yjl/auth2engine"
)

var (
	// 这里使用的是通知中心的 clientid, clientsecret信息
	// 本地测试需要使用通知中心的测试账户、密码登陆
	ClientId = "eaffa6e3781c05cc3abcfcd7f64ce246db5c9ba1"
	ClientSecret = "e5f50f7ce233af132b3c0998ec9030162348e2ef"
	Scope = []string{"all"}

	app_host = "localhost"
	app_port = "9094"

	/*
		// 测试连接统信oauth2服务使用
		oauth_server = "http://login-platform-pre.uniontech.com"
		oauth_login_staic_path = "/login"
		oauth_auth_code_path = "/authorize"
		oauth_token_path = "/token"
		oauth_info_path = "/info"

	*/
	// 测试连接本地demo server 使用
	oauth_server = "http://localhost:9096"
	oauth_login_staic_path = "/oauth/authorize"
	oauth_auth_code_path = "/oauth/authorize"
	oauth_token_path = "/oauth/token"
	oauth_info_path = "/test"

	DefaultAppUrlPath = "/app/userinfo" // 认证完成后的默认跳转页面
	app_callback_url = "http://" + app_host + ":" + app_port + "/auth/callback"  //oauth 服务器返回auth code信息重定向的app 地址

	session_store_type = "memory"  //memory or redis

	redis_address = "localhost:6379"
	redis_password = "131121"
	redis_db = "1"

	)

func loadOAuthConfig() *auth2engine.AuthEngineConfig {
	config :=  &auth2engine.AuthEngineConfig{
		OAuth2: auth2engine.OAuth2Config{
			Server:       oauth_server,

			LoginPath:    oauth_login_staic_path, //oauth服务器渲染静态登陆页面的url path
			AuthPath:     oauth_auth_code_path,  // oauth服务器获取auth code的URL path
			TokenPath:    oauth_token_path,  // oauth服务器获取token信息的URL path
			InfoPath:	  oauth_info_path,   //获取token 对应用户信息的入口url path

			ClientId:     ClientId,  // app注册返回的client_id
			ClientSecret: ClientSecret,  //app注册返回的clientSecret
			Scope: Scope,

			Callback:     app_callback_url, //oauth 服务器返回auth code信息重定向的app 地址
		},
		SessionStoreType: session_store_type,
		DefaultAppUrl: DefaultAppUrlPath,
	}

	// 如果session store为redis ,则初始化redis配置
	if config.SessionStoreType == "redis" {
		config.Redis = auth2engine.RedisConf{
			Address : redis_address,
			Password: redis_password,
			Db: redis_db,
		}
	}

	return config

}

func main() {

	// 加载配置
	authConfig := loadOAuthConfig()
	// 基于配置初始化oauth2 app engine
	eng := auth2engine.InitEngine(authConfig)

	// 基于oauth2 app engine 设置自己的应用route group， 并对这个route group增加 auth中间件
	appGroup:= eng.Group("app").Use(auth2engine.AuthMiddlewarer())
	//  后面用户实现自己app中的的路由处理逻辑
	{
		appGroup.GET("/userinfo", func(c *gin.Context) {
			info, err := auth2engine.GetUserInfo(c)
			fmt.Println("INFO.....")
			if err != nil {
				c.JSON(200, gin.H {"errMsg":"not login or token expire"})
			}
			c.JSON(200, info)
		})
	}

	eng.Run(app_host + ":" + app_port )
}