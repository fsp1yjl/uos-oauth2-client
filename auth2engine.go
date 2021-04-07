
package auth2engine

import (
	"context"
	"encoding/gob"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"net/http"
)

/*
请求流程：
测试前提： 在rbac web管理中注册应用，获取clientid, clientsecret, 如果已经注册，忽略本步骤
访问应用默认页面： localhost:9094/auth/is_login 路由，
	判断用户是否登陆，如果登陆则返回token 信息
	如果未登陆，则重定向到oauth服务器的登陆静态页面路由， 这里是 oauth2-server:port/login
auth2 登陆认证完成后，会把请求redirect到app 指定的回调地址，这里是http://localhost:9094/auth/callback
*/
var (
	config *AuthEngineConfig
	// 这里使用的是通知中心的 clientid, clientsecret信息
	// 本地测试需要使用通知中心的测试账户、密码登陆
	ClientId = "eaffa6e3781c05cc3abcfcd7f64ce246db5c9ba1"
	ClientSecret = "e5f50f7ce233af132b3c0998ec9030162348e2ef"
	oauth_server = "http://login-platform-pre.uniontech.com"

	app_host = "localhost"
	app_port = "9094"
	oauth_login_staic_path = "/login"
	oauth_callback_to_app_url = "http://" + app_host + ":" + app_port + "/auth/callback"  //oauth 服务器返回auth code信息重定向的app 地址

	SessionStoreType = "redis"

)


type  OAuth2Config struct{
	Server string
	LoginPath string
	AuthPath string
	TokenPath string
	ClientId string
	ClientSecret string
	Callback string
}

type AuthEngineConfig struct {
	OAuth2 OAuth2Config
	RedisConf struct {
		Address string
		Password string
		Db string
	}
}


func init() {
	LoadConfig()
}

func LoadConfig()  {

	config =  &AuthEngineConfig{
		OAuth2 : OAuth2Config {
			Server: oauth_server,
			LoginPath: oauth_login_staic_path,  //oauth服务器渲染登录界面的url路径
			ClientId: ClientId,
			ClientSecret: ClientSecret,
			Callback: oauth_callback_to_app_url, //oauth 服务器返回auth code信息重定向的app 地址
		},


	}
}

// 初始化sessionStore, 可以默认使用 memstore, 可以自行修改为redis
func initSessionStore() sessions.Store  {

	if SessionStoreType == "redis" {
		store, err := redis.NewStoreWithDB(10,
			"tcp",
			"localhost:6379",
			"131121",
			"1",
			[]byte("secret"))
		if err != nil {
			panic("init redis session store error:")
		}

		return store
	}

	sessionStore := memstore.NewStore([]byte("secret"))
	return sessionStore
}

// 初始化服务器
func initServerControler() *gin.Engine{
	eng := gin.Default()
	eng.GET("/", DefaultPage)

	store := initSessionStore()
	eng.Use(sessions.Sessions("platform", store))

	auth := eng.Group("/auth")
	auth.GET("/is_login", LoggedCheckHandle )
	auth.GET("/callback", CallbackHandle)


	return eng
}

func InitEngine() *gin.Engine{
	eng := initServerControler()
	return eng
	//s.Run(config.Host + ":" + config.Port) // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

func DefaultPage(c *gin.Context) {
	c.Redirect(302, "/auth/is_login")
}

func LoginCheck(sess sessions.Session)  bool{

	gob.Register(oauth2.Token{})
	token := sess.Get("token")
	if token == nil {
		return false
	}

	t := token.(oauth2.Token)

	// 判断token合法且未过期
	if t.Valid() {
		return true
	}

	return false
}

//判断是否登录
func LoggedCheckHandle(c *gin.Context)  {
	session := sessions.Default(c)

	//判断session中是否存在token ,如果存在则直接返回token信息，否则直接跳转到三方认证页面
	logged := LoginCheck(session)
	state := "hello"

	var getQueryString  func() string
	getQueryString = func () string  {
		str := fmt.Sprintf("?response_type=code&client_id=%v&redirect_uri=%v&state=%v", config.OAuth2.ClientId, config.OAuth2.Callback, state)
		fmt.Println("str4----------:", str)
		return str
	}

	//gob.Register(oauth2.Token{})

	if logged {
		to:= session.Get("token").(oauth2.Token)
		c.JSON(200, to)
		return
	}

	session.Set("state", state )
	session.Save()
	c.Redirect(302, config.OAuth2.Server + config.OAuth2.LoginPath + getQueryString())
	return
}

func CallbackHandle(c *gin.Context) {

	fmt.Println("into callback")
	r := c.Request
	r.ParseForm()

	session := sessions.Default(c)
	stateSession := session.Get("state" )
	state := r.Form.Get("state")

	fmt.Println("------------session state:", state)
	// nsrf secure check by state param
	if state == "" || state != stateSession {
		c.JSON(200,gin.H{"msg:":"nsrf check failed"})
		return
	}

	code := r.Form.Get("code")
	if code == "" {
		http.Error(c.Writer, "Code not found", http.StatusBadRequest)
		return
	}

	authConf := oauth2.Config{
		ClientID: "eaffa6e3781c05cc3abcfcd7f64ce246db5c9ba1",
		ClientSecret: "e5f50f7ce233af132b3c0998ec9030162348e2ef",
		Scopes:       []string{"all"},
		RedirectURL:  "http://localhost:9094/auth/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.OAuth2.Server + "/authorize",
			TokenURL: config.OAuth2.Server + "/token",
		},
	}


	fmt.Println("1111 before get token")
	// exchange 获取token
	token, err := authConf.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(500, gin.H{"msg:": "internal error"})
		return
	}
	fmt.Println("222 after  get token", token)

	// oauth 三方认证完成后， 把token信息放入session中备用
	session.Set("token", token )
	session.Save()
	c.Redirect(302,"/auth/is_login")


}