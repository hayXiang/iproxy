package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

var lOG_LEVEL = 3 //0: no log, 1: error, 2: info, 3: debug

func LOG_DEBUG(out string) {
	if lOG_LEVEL >= 3 {
		log.Printf("[DEBUG]%s", out)
	}
}

func LOG_INFO(out string) {
	if lOG_LEVEL >= 2 {
		log.Printf("[INFO]%s", out)
	}
}

func LOG_ERROR(out string) {
	if lOG_LEVEL >= 1 {
		log.Printf("[ERROR]%s", out)
	}
}

var transport = http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	Dial: func(network, addr string) (net.Conn, error) {
		return net.DialTimeout(network, addr, time.Duration(5*time.Second))
	},
}

type HttpRequestCallback func(*http.Request, *http.Client)

func HttpGet(url string, config *HttpConfig) (*http.Response, error) {
	LOG_INFO("begin to HttpGet " + url)
	defer func() {
		LOG_INFO("end to HttpGet " + url)
	}()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if len(config.headers) == 0 {
		req.Header.Add("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 9; PCRT00 Build/PQ3A.190605.01111538)")
	} else {
		for key, value := range config.headers {
			req.Header.Add(key, value)
		}
	}

	if !config.follow_redirect {
		client := http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &transport,
		}
		res, err := client.Do(req)
		if err != nil {
			return res, err
		}
		return res, err
	} else {
		client := http.Client{
			Transport: &transport,
		}
		res, err := client.Do(req)
		if err != nil {
			return res, err
		}
		return res, err
	}
}

type HttpConfig struct {
	headers         map[string]string
	url             string
	follow_redirect bool
}

var is_m3u_porxy = false
var http_configs = make(map[string]HttpConfig)

func http_path(url string) string {
	path := strings.Replace(url, "http://", "", 1)
	path = strings.Replace(path, "https://", "", 1)
	index := strings.Index(path, "?")
	if index != -1 {
		path = path[:index]
	}
	return path
}

func proxy(w http.ResponseWriter, req *http.Request) {
	LOG_INFO("[S]" + req.RequestURI)
	if !strings.Contains(req.RequestURI, ("/http:/")) && !strings.Contains(req.RequestURI, ("/https:/")) {
		w.WriteHeader(500)
		w.Write([]byte("must be start witch /http:/ or /https"))
	} else {
		url := req.RequestURI[1:]
		url = strings.Replace(url, "http:/", "http://", 1)
		url = strings.Replace(url, "https:/", "https://", 1)

		config := http_configs[http_path(url)]
		resp, err := HttpGet(url, &config)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == 301 || resp.StatusCode == 302 {
			location := resp.Header.Get("Location")
			location = strings.Replace(location, "http://", "/http:/", 1)
			location = strings.Replace(location, "https://", "/https:/", 1)
			w.Header().Set("Location", location)
		}
		w.WriteHeader(resp.StatusCode)
		contentType := resp.Header.Get("Content-Type")
		if is_m3u_porxy && contentType == "application/vnd.apple.mpegurl" {
			m3u8_body, _ := io.ReadAll(resp.Body)
			body := strings.ReplaceAll(string(m3u8_body), "https://", "/https:/")
			io.Copy(w, strings.NewReader(body))
		} else {
			io.Copy(w, resp.Body)
		}
	}
	LOG_INFO("[E]" + req.RequestURI)
}

func main() {
	listen_address := flag.String("l", ":8080", "listen address")
	flag.BoolVar(&is_m3u_porxy, "m3u8_proxy", true, "replace m3u8 ts file")
	http_config_file := flag.String("h", "./http.json", "http config file")

	flag.Parse()

	data, err := ioutil.ReadFile(*http_config_file)
	if err != nil {
		panic("无法读取文件")
	}

	// 将 []byte 类型的数据转换成 string 类型
	str_http_config := string(data)

	if str_http_config != "" {
		var config interface{}
		json.Unmarshal([]byte(str_http_config), &config)
		datas := config.([]interface{})
		for _, data := range datas {
			var http_config HttpConfig
			http_config.follow_redirect = false
			http_config.headers = make(map[string]string)
			for k, v := range data.(map[string]interface{}) {
				if k == "headers" {
					for header_key, header_value := range v.(map[string]interface{}) {
						http_config.headers[header_key] = header_value.(string)
					}
				}
				if k == "url" {
					http_config.url = v.(string)
				}
				if k == "follow_redirect" && v.(bool) {
					http_config.follow_redirect = true
				}
			}
			http_configs[http_path(http_config.url)] = http_config
		}
	}

	http.HandleFunc("/", proxy)
	fmt.Println("server listen :" + *listen_address)
	http.ListenAndServe(*listen_address, nil)
	fmt.Println("iproxy exit!")
}
