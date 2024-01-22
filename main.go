package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func proxy(w http.ResponseWriter, req *http.Request) {
	if strings.Index(req.RequestURI, ("http")) == -1 {
		w.WriteHeader(500)
	} else {
		url := req.RequestURI[1:]
		url = strings.Replace(url, "http:/", "http://", 1)
		url = strings.Replace(url, "https:/", "https://", 1)
		fmt.Println(url)
		resp, err := http.Get(url)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		body, _ := io.ReadAll(resp.Body)
		w.Write(body)
		w.WriteHeader(resp.StatusCode)
	}
}
func main() {
	listen_address := ":80"
	if len(os.Args) > 1 {
		listen_address = os.Args[1]
	}
	http.HandleFunc("/", proxy)
	fmt.Println("server listen :" + listen_address)
	http.ListenAndServe(listen_address, nil)
}
