package main

import (
	auth2engine "githut.com/fsp1yjl/auth2engine"
)

var (
	
	ClientId = "eaffa6e3781c05cc3abcfcd7f64ce246db5c9ba1"
	ClientSecret = "e5f50f7ce233af132b3c0998ec9030162348e2ef"
	Scope = []string{"all"}

	app_host = "localhost"
	app_port = "9094"

	//oauth_server = "http://login-platform-pre.uniontech.com"
	//oauth_login_staic_path = "/login"
	//oauth_auth_code_path = "/authorize"
	//oauth_token_path = "/token"
	oauth_server = "http://localhost:9096"
	oauth_login_staic_path = "/oauth/authorize"
	oauth_auth_code_path = "/oauth/authorize"
	oauth_token_path = "/oauth/token"
	oauth_callback_to_app_url = "http://" + app_host + ":" + app_port + "/auth/callback"  //oauth 服务器返回auth code信息重定向的app 地址

	session_store_type = "memory"  //memory or redis

	redis_address = "localhost:6379"
	redis_password = "131121"
	redis_db = "1"
	)

func loadOAuthConfig() *auth2engine.AuthEngineConfig {
	config :=  &auth2engine.AuthEngineConfig{
		OAuth2: auth2engine.OAuth2Config{
			Server:       oauth_server,
			LoginPath:    oauth_login_staic_path, //oauth服务器渲染登录界面的url路径
			AuthPath:     oauth_auth_code_path,  // oauth服务器获取auth code的URL path
			TokenPath:    oauth_token_path,  // oauth服务器获取token信息的URL path
			ClientId:     ClientId,  // app注册返回的client_id
			ClientSecret: ClientSecret,  //app注册返回的clientSecret
			Scope: Scope,
			Callback:     oauth_callback_to_app_url, //oauth 服务器返回auth code信息重定向的app 地址
		},
		Redis: auth2engine.RedisConf{
			Address : redis_address,
			Password: redis_password,
			Db: redis_db,
		},
		SessionStoreType: session_store_type,
	}

	return config

}

func main() {

	authConfig := loadOAuthConfig()
	eng := auth2engine.InitEngine(authConfig)
	eng.Run(app_host + ":" + app_port )
}
