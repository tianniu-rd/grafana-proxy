package main

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Luzifer/rconfig"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	RequestIDKey   = "request_id"
	GrafanaSession = "grafana_session"
)

var (
	cfg = struct {
		User      string `flag:"user,u" default:"" env:"USER" description:"Username for Grafana login"`
		Pass      string `flag:"pass,p" default:"" env:"PASS" description:"Password for Grafana login"`
		BaseURL   string `flag:"baseurl" default:"" env:"BASEURL" description:"BaseURL (excluding last /) of Grafana"`
		Listen    string `flag:"listen" default:"127.0.0.1:8081" description:"IP/Port to listen on"`
		Token     string `flag:"token" default:"" env:"TOKEN" description:"(optional) require a ?token=xyz parameter to show the dashboard"`
		LogFormat string `flag:"log-format" default:"text" env:"LOG_FORMAT" description:"Output format for logs (text/json)"`
	}{}
	base *url.URL
)

func init() {
	if err := rconfig.Parse(&cfg); err != nil {
		log.Fatalf("Unable to parse commandline options: %s", err)
	}

	switch cfg.LogFormat {
	case "text":
		log.SetFormatter(&log.TextFormatter{})
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	default:
		log.Fatalf("Unknown log format: %s", cfg.LogFormat)
	}

	log.SetLevel(log.InfoLevel)

	if cfg.User == "" || cfg.Pass == "" || cfg.BaseURL == "" {
		rconfig.Usage()
		os.Exit(1)
	}
	if cfg.Token == "" {
		w := md5.New()
		io.WriteString(w, cfg.Pass)
		cfg.Token = fmt.Sprintf("%x", w.Sum(nil))
	}
	log.Infof("grafana proxy config: %+v", cfg)
}

// removeGrafanaSession 删除当前请求中的grafana session
func removeGrafanaSession(header *http.Header) {
	if header != nil {
		cookie := header.Values("Cookie")
		header.Del("Cookie")
		for _, h := range cookie {
			if !strings.Contains(h, GrafanaSession) {
				header.Add("Cookie", h)
			}
		}
	}
}

// loadLogin 登录grafana，获取session，并放到request当前请求中
func loadLogin(ctx context.Context, r *http.Request) (string, error) {
	loginBody, _ := json.Marshal(map[string]string{
		"user":     cfg.User,
		"password": cfg.Pass,
	})
	body := strings.NewReader(string(loginBody))
	resp, err := http.DefaultClient.Post(cfg.BaseURL+"/login", "application/json", body)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"user":       cfg.User,
			"request_id": requestIDFromContext(ctx),
		}).Error("Login failed")
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		loginRes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return "", errors.New(string(loginRes))
	}
	removeGrafanaSession(&r.Header)
	for _, c := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(c, GrafanaSession) {
			r.Header.Add("Cookie", c)
			return c, nil
		}
	}
	return "", errors.New("not found grafana session after login")
}

// redirectLogin 判断请求返回是否认证失败或者重定向到登录页面
func redirectLogin(response *http.Response) bool {
	if response.StatusCode == 401 {
		return true
	}
	if response.StatusCode == 302 {
		location, _ := response.Location()
		if strings.Contains(location.String(), "login") {
			return true
		}
	}
	return false
}

type proxy struct{}

func (p proxy) originProxy(requestLog *log.Entry, res http.ResponseWriter, r *http.Request) {
	transport := http.DefaultTransport
	resp, err := transport.RoundTrip(r)
	if err != nil {
		requestLog.WithError(err).Error("Request failed")
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		for _, v1 := range v {
			res.Header().Add(k, v1)
		}
	}
	res.WriteHeader(resp.StatusCode)
	_, err = io.Copy(res, resp.Body)
	if err != nil {
		requestLog.WithError(err).Error("Write response failed")
	}
}

func (p proxy) loginProxy(ctx context.Context, requestLog *log.Entry, res http.ResponseWriter, r *http.Request) {

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		requestLog.WithError(err).Error("Request failed")
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	if redirectLogin(resp) {
		errmsg, _ := ioutil.ReadAll(resp.Body)
		requestLog.WithFields(log.Fields{
			"error":  string(errmsg),
			"header": r.Header,
		}).Info("Unauthorized, trying to login")
		resp.Body.Close()

		session, err := loadLogin(ctx, r)
		if err != nil {
			requestLog.WithError(err).Error("login error")
		}
		if session != "" {
			res.Header().Add("Set-Cookie", session)
		}

		resp, err = http.DefaultTransport.RoundTrip(r)
		if err != nil {
			requestLog.WithError(err).Error("Request failed")
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if r.URL.Query().Get("token") != "" {
		http.SetCookie(res, &http.Cookie{
			Name:   "grafana-proxy-auth",
			Value:  r.URL.Query().Get("token"),
			MaxAge: 31536000, // 1 Year
			Path:   "/",
		})
	}
	for k, v := range resp.Header {
		for _, v1 := range v {
			res.Header().Add(k, v1)
		}
	}

	res.WriteHeader(resp.StatusCode)
	io.Copy(res, resp.Body)
}

func (p proxy) ServeHTTP(res http.ResponseWriter, r *http.Request) {
	requestID := uuid.NewV4().String()
	bgCtx := context.Background()
	ctx := context.WithValue(bgCtx, RequestIDKey, requestID)

	requestLog := log.WithFields(log.Fields{
		"http_user_agent": r.Header.Get("User-Agent"),
		"host":            r.Host,
		"remote_addr":     r.Header.Get("X-Forwarded-For"),
		"request":         r.URL.Path,
		"request_full":    r.URL.String(),
		"request_method":  r.Method,
		"request_id":      requestIDFromContext(ctx),
	})
	r.URL.Host = base.Host
	r.URL.Scheme = base.Scheme
	r.RequestURI = ""
	r.Host = base.Host
	r.Header.Set("Origin", cfg.BaseURL)

	suppliedToken := ""
	if authCookie, err := r.Cookie("grafana-proxy-auth"); err == nil {
		suppliedToken = authCookie.Value
	}
	if token := r.URL.Query().Get("token"); token != "" {
		suppliedToken = token
	}
	if suppliedToken == "" {
		// 未获取代理认证token，直接转发到后端
		p.originProxy(requestLog, res, r)
		return
	}

	if suppliedToken != cfg.Token {
		requestLog.Errorf("Token authorized error, token=%s, cfgToken=%s", suppliedToken, cfg.Token)
		http.Error(res, "Token authorized error", http.StatusForbidden)
		return
	}
	p.loginProxy(ctx, requestLog, res, r)
}

func requestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(RequestIDKey).(string); ok {
		return id
	}
	return ""
}

func main() {
	//loadLogin(context.Background())
	var err error
	base, err = url.Parse(cfg.BaseURL)
	if err != nil {
		log.WithError(err).WithField("base_url", base).Fatalf("BaseURL is not parsesable")
	}

	log.Fatal(http.ListenAndServe(cfg.Listen, proxy{}))
}
