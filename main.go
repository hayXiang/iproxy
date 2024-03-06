package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
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

var transport_disable_keep_alive = http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	Dial: func(network, addr string) (net.Conn, error) {
		return net.DialTimeout(network, addr, time.Duration(5*time.Second))
	},
	DisableKeepAlives: true,
}

type HttpRequestCallback func(*http.Request, *http.Client)

func HttpGet(url string, config *HttpConfig, time_out int) (*http.Response, error) {
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

	client := http.Client{}

	if config.keep_alive {
		client.Transport = &transport
	} else {
		client.Transport = &transport_disable_keep_alive
	}

	if !config.follow_redirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	if time_out != -1 {
		client.Timeout = time.Second * time.Duration(time_out)
	}
	res, err := client.Do(req)
	if err != nil {
		return res, err
	}
	return res, err

}

type HttpConfig struct {
	headers           map[string]string
	url               string
	follow_redirect   bool
	m3u8_proxy        bool
	error_code_to_302 bool
	time_out          int
	max_session       int
	keep_alive        bool
	mutex             sync.Mutex
}

var http_configs = make(map[string]*HttpConfig)

func http_path(url string) string {
	path := strings.Replace(url, "http://", "", 1)
	path = strings.Replace(path, "https://", "", 1)
	index := strings.Index(path, "?")
	if index != -1 {
		path = path[:index]
	}
	return path
}

func get_http_config(uri string) *HttpConfig {
	for key, value := range http_configs {
		if key == "*" {
			continue
		}

		found, err := regexp.MatchString(key, uri)
		if err != nil || !found {
			continue
		}
		return value
	}
	return http_configs["*"]
}

func dec_session_count(config *HttpConfig, is_need_to_restore_session *bool) {
	if *is_need_to_restore_session {
		config.mutex.Lock()
		config.max_session -= 1
		config.mutex.Unlock()
	}
}

func inc_session_count(config *HttpConfig, is_need_to_restore_session *bool) {
	if *is_need_to_restore_session {
		time.Sleep(1 * time.Second)
		config.mutex.Lock()
		config.max_session += 1
		config.mutex.Unlock()
		*is_need_to_restore_session = false
	}
}

func proxy(w http.ResponseWriter, req *http.Request) {
	LOG_INFO("[S]" + req.RequestURI)
	if !strings.Contains(req.RequestURI, ("/http:/")) && !strings.Contains(req.RequestURI, ("/https:/")) {
		err_msg := "must be start witch /http:/ or /https"
		w.WriteHeader(500)
		w.Write([]byte(err_msg))
		LOG_ERROR(err_msg)
	} else {
		rawUrl := req.RequestURI[1:]
		rawUrl = strings.Replace(rawUrl, "http:/", "http://", 1)
		rawUrl = strings.Replace(rawUrl, "https:/", "https://", 1)

		config := get_http_config(rawUrl)
		if strings.Contains(rawUrl, "follow_redirect=false") {
			rawUrl = strings.Replace(rawUrl, "?follow_redirect", "", 1)
			rawUrl = strings.Replace(rawUrl, "&follow_redirect", "", 1)
			config.follow_redirect = false
		}

		config.mutex.Lock()
		if config.max_session == 0 {
			location := "/" + req.RequestURI[1:]
			err_msg := "session count is 0, redirect to " + location
			config.mutex.Unlock()
			LOG_ERROR(err_msg)
			time.Sleep(1000 * time.Millisecond)
			w.Header().Set("Location", location)
			w.WriteHeader(302)
			return
		}
		config.mutex.Unlock()

		is_need_to_restore_session := false
		dec_session_count(config, &is_need_to_restore_session)
		time_out := config.time_out
		if strings.Contains(rawUrl, "live_mode=ts") || strings.Contains(rawUrl, "live_mode=flv") {
			time_out = -1
		}

		resp, err := HttpGet(rawUrl, config, time_out)
		defer func() {
			if err == nil {
				resp.Body.Close()
			}
			inc_session_count(config, &is_need_to_restore_session)
		}()
		if err != nil {
			LOG_ERROR(fmt.Sprint(err))
			if config.error_code_to_302 {
				location := "/" + req.RequestURI[1:]
				LOG_ERROR("get " + location + " error, redirect to get it")
				w.Header().Set("Location", location)
				w.WriteHeader(302)

			} else {
				w.WriteHeader(500)
				w.Write([]byte(err.Error()))
			}
			return
		}

		if resp.StatusCode == 301 || resp.StatusCode == 302 {
			location := resp.Header.Get("Location")
			location = strings.Replace(location, "http://", "/http:/", 1)
			location = strings.Replace(location, "https://", "/https:/", 1)
			w.Header().Set("Location", location)
		} else if (resp.StatusCode < 200 || resp.StatusCode > 299) && config.error_code_to_302 {
			m3u8_body, _ := io.ReadAll(resp.Body)
			LOG_ERROR(string(m3u8_body))
			location := "/" + req.RequestURI[1:]
			LOG_ERROR("get " + location + " error, redirect to get it")
			w.Header().Set("Location", location)
			w.WriteHeader(302)
			return
		}

		w.WriteHeader(resp.StatusCode)

		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "mpegurl") {
			m3u8_body, _ := io.ReadAll(resp.Body)
			LOG_DEBUG(string(m3u8_body))
			if config.max_session == 0 {
				time.Sleep(1 * time.Second)
			}
			inc_session_count(config, &is_need_to_restore_session)
			line := bufio.NewScanner(strings.NewReader(string(m3u8_body)))
			lastRequestUrl := resp.Request.URL
			for line.Scan() {
				ext_info := line.Text()
				if strings.Contains(ext_info, ".ts") {
					if strings.Index(ext_info, "/") == 0 {
						ext_info = lastRequestUrl.Scheme + "://" + lastRequestUrl.Host + ext_info
					} else if strings.Index(ext_info, "http://") != 0 && strings.Index(ext_info, "https://") != 0 && lastRequestUrl.String() != rawUrl {
						lastRequstRawUrl := lastRequestUrl.String()
						ext_info = lastRequstRawUrl[0:strings.LastIndex(lastRequstRawUrl, "/")] + "/" + ext_info
					}

					if config.m3u8_proxy {
						ext_info = strings.ReplaceAll(ext_info, "http://", "/http:/")
						ext_info = strings.ReplaceAll(ext_info, "https://", "/https:/")
					}
				}
				io.Copy(w, strings.NewReader(ext_info+"\n"))
			}
		} else {
			io.Copy(w, resp.Body)
		}

		if strings.Contains(rawUrl, "live_mode=ts") || strings.Contains(rawUrl, "live_mode=flv") {
			panic("the stream must not be close")
		}
	}
	LOG_INFO("[E]" + req.RequestURI)
}

func main() {
	listen_address := flag.String("l", ":8080", "listen address")
	is_m3u8_proxy := flag.Bool("m3u8_proxy", true, "replace m3u8 ts file")
	http_config_file := flag.String("c", "./http.json", "http config file")
	http_error_code_to_302 := flag.Bool("http_error_code_to_302", false, "replace http error code to 302")
	http_time_out := flag.Int("http_tim_out", 30, "http time out")
	http_keep_alive := flag.Bool("http_keep_alive", true, "http keep alive")

	flag.Parse()

	data, err := ioutil.ReadFile(*http_config_file)
	if err == nil {
		str_http_config := string(data)
		if str_http_config != "" {
			var config interface{}
			json.Unmarshal([]byte(str_http_config), &config)
			datas := config.([]interface{})
			var default_config HttpConfig
			default_config.follow_redirect = true
			default_config.m3u8_proxy = *is_m3u8_proxy
			default_config.error_code_to_302 = *http_error_code_to_302
			default_config.time_out = *http_time_out
			default_config.max_session = -1
			default_config.keep_alive = *http_keep_alive
			http_configs["*"] = &default_config

			for _, data := range datas {
				var http_config HttpConfig
				http_config.follow_redirect = default_config.follow_redirect
				http_config.m3u8_proxy = default_config.m3u8_proxy
				http_config.error_code_to_302 = default_config.error_code_to_302
				http_config.time_out = default_config.time_out
				http_config.keep_alive = default_config.keep_alive
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
					if k == "follow_redirect" {
						http_config.follow_redirect = v.(bool)
					}

					if k == "m3u8_proxy" {
						http_config.m3u8_proxy = v.(bool)
					}

					if k == "max_session" {
						http_config.max_session = int(v.(float64))
					}

					if k == "error_code_to_302" {
						http_config.error_code_to_302 = v.(bool)
					}

					if k == "time_out" {
						http_config.time_out = int(v.(float64))
					}

					if k == "keep_alive" {
						http_config.keep_alive = v.(bool)
					}
				}
				http_configs[http_path(http_config.url)] = &http_config
			}
		}
	}

	http.HandleFunc("/", proxy)
	fmt.Println("server listen :" + *listen_address)
	http.ListenAndServe(*listen_address, nil)
	fmt.Println("iproxy exit!")
}
