package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var transport = http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	Dial: func(network, addr string) (net.Conn, error) {
		return net.DialTimeout(network, addr, time.Duration(5*time.Second))
	},
}

type HttpRequestCallback func(*http.Request, *http.Client)

func HttpGet(url string) (*http.Response, error) {
	fmt.Println("begin to HttpGet " + url)
	defer func() {
		fmt.Println("end to HttpGet " + url)
	}()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

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
}

func proxy(w http.ResponseWriter, req *http.Request) {
	fmt.Println(req.RequestURI)
	if !strings.Contains(req.RequestURI, ("/http:/")) && !strings.Contains(req.RequestURI, ("/https:/")) {
		w.WriteHeader(500)
		w.Write([]byte("must be start witch /http:/ or /https"))
	} else {
		url := req.RequestURI[1:]
		url = strings.Replace(url, "http:/", "http://", 1)
		url = strings.Replace(url, "https:/", "https://", 1)
		resp, err := HttpGet(url)
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
		io.Copy(w, resp.Body)
	}
}
func main() {
	listen_address := ":8080"
	if len(os.Args) > 1 {
		listen_address = os.Args[1]
	}
	http.HandleFunc("/", proxy)
	fmt.Println("server listen :" + listen_address)
	http.ListenAndServe(listen_address, nil)
}
