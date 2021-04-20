
package auth2engine

import (
	"context"
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"net/http"
)


var (
	config *AuthEngineConfig
	SessionStoreRedisType = "redis"
)
var (
	ErrTokenInvalid = errors.New("token invalid ")
	ErrInternal = errors.New("internal error")
)

type  OAuth2Config struct{
	Server string
	LoginPath string
	AuthPath string
	TokenPath string
	InfoPath string
	ClientId string
	ClientSecret string
	Scope []string
	Callback string
}
type RedisConf struct {
	Address string
	Password string
	Db string
}

type AuthEngineConfig struct {
	OAuth2 OAuth2Config
	Redis  RedisConf
	SessionStoreType string
	DefaultAppUrl string
}

type UserInfo struct {
UserID   string   `json:"user_id"`
ClientID string   `json:"client_id"`
Roles    []string `json:"roles"`
Scope    string   `json:"scope"`
}

// InitEngine 基于传入的auth 配置，实例化一个添加了oauth处理路由的gin engine
func InitEngine(conf *AuthEngineConfig) *gin.Engine{
	config = conf
	eng := initServerControler()
	return eng
	//s.Run(config.Host + ":" + config.Port) // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

// initServerControler 初始化服务器
func initServerControler() *gin.Engine{
	// 需要先初始化auth2engine配置信息  
	if !authConfigCheck() {
		panic("auth2engine config check failed")
	}
	eng := gin.Default()

	// todo 后期考虑将session相关配置操作交给用户，由用户自己初始化session store 这里只约定使用session
	store := initSessionStore()
	eng.Use(sessions.Sessions("platform", store))


	// todo 这里为oauth相关使用的route group是默认的 ‘auth’,后续考虑设置为用户可配置
	auth := eng.Group("/auth")
	//auth.GET("/is_login", loggedCheckHandle )
	auth.GET("/callback", callbackHandle)
	return eng
}


// 初始化sessionStore, 可以默认使用 memstore, 可以自行修改为redis
func initSessionStore() sessions.Store  {
	if SessionStoreRedisType == config.SessionStoreType {
		store, err := redis.NewStoreWithDB(10,
			"tcp",
			config.Redis.Address,
			config.Redis.Password,
			config.Redis.Db,
			[]byte("secret"))
		if err != nil {
			panic("init redis session store error:")
		}

		return store
	}

	sessionStore := memstore.NewStore([]byte("secret"))
	return sessionStore
}

func authConfigCheck () bool {
	if config == nil {
		return false
	}

	if config.OAuth2.Server == "" {
		return false
	}
	// todo 增加更完备的参数检验

	return true
}

//TokenCheck 判断session中是否保存了token
// 如果token不存在，则返回false
// 如果token存在且未过期，返回false
// 如果token存在但是过期，则清空session 中的token信息，并返回false
func TokenCheck(sess sessions.Session)  bool{

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

	// 如果判断token过期，则删除session 中的token信息
	sess.Delete("token")
	sess.Save()
	return false
}

//stateCheck  用于检测请求用户session中存储的随机值state,用于nsrf secure check
func stateCheck(sess sessions.Session, state string ) bool {
	sessionState := sess.Get("state")
	if state != "" && state == sessionState {
		return true
	}
	return false
}

// genState 生成8位随机码，用于防止nsrf攻击
func genState() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// callbackHandle 接受oauth2服务器返回的auth code信息，并基于这个code去和auth2 server交互，得到tokeninfo信息
// 并将当前tokeninfo存入session 用于后续使用
func callbackHandle(c *gin.Context) {
	r := c.Request
	r.ParseForm()

	session := sessions.Default(c)
	//nsrf secure validate
	state := r.Form.Get("state")
	if !stateCheck(session, state) {
		c.JSON(http.StatusBadRequest ,gin.H{"msg:":"nsrf check failed"})
		return
	}

	code := r.Form.Get("code")
	if code == "" {
		http.Error(c.Writer, "Code not found", http.StatusBadRequest)
		return
	}

	authConf := oauth2.Config{
		ClientID: config.OAuth2.ClientId,
		ClientSecret: config.OAuth2.ClientSecret,
		Scopes:       config.OAuth2.Scope,
		RedirectURL:  config.OAuth2.Callback,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.OAuth2.Server + config.OAuth2.AuthPath,
			TokenURL: config.OAuth2.Server + config.OAuth2.TokenPath,
		},
	}

	// exchange 获取token
	token, err := authConf.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(500, gin.H{"msg:": "internal error"})
		return
	}

	// oauth 三方认证完成后， 把token信息放入session中备用
	session.Set("token", token )
	session.Save()
	// oauth 认证完成后，页面跳转到app 默认页面
	c.Redirect(302, config.DefaultAppUrl)
}


// AuthMiddleware 中间件处理逻辑会判断用户session中是否包含有效token信息，如果无合法token,则跳转到oauth2三方认证页面
func AuthMiddlewarer () gin.HandlerFunc {
	return func (c *gin.Context)  {
		session := sessions.Default(c)
		//判断session中是否存在token ,如果存在则直接返回token信息，否则直接跳转到三方认证页面
		logged := TokenCheck(session)
		if logged {
			return
		}

		state := genState()
		var getQueryString  func() string
		// todo 后期考虑使用oauth2.Config.AuthCodeURL方法去拼装请求链接
		getQueryString = func () string  {
			str := fmt.Sprintf("?response_type=code&client_id=%v&redirect_uri=%v&state=%v", config.OAuth2.ClientId, config.OAuth2.Callback, state)
			return str
		}

		session.Set("state", state )
		session.Save()
		c.Redirect(302, config.OAuth2.Server + config.OAuth2.LoginPath + getQueryString())
		return
	}

}

// GetUserInfo 基于session中的token信息返回当前请求连接的用户细心
func GetUserInfo(c *gin.Context) (info UserInfo, err error){
	session := sessions.Default(c)

	//判断session中是否存在token ,如果存在则直接返回token信息，否则直接跳转到三方认证页面
	logged := TokenCheck(session)
	if !logged {
		return UserInfo{} ,  ErrTokenInvalid
	}
	to:= session.Get("token").(oauth2.Token)
	resp, err := http.Get(fmt.Sprintf("%s%s?access_token=%s", config.OAuth2.Server, config.OAuth2.InfoPath, to.AccessToken))
	if err != nil {
		return UserInfo{} , ErrInternal
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	user := UserInfo{}
	err = dec.Decode(&user)
	if err != nil {
		return UserInfo{}, ErrInternal
	}
	return user, nil
}
