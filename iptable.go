package main

import (
        "fmt"
        "net/http"
        "io/ioutil"
	"encoding/json"
	"github.com/coreos/go-iptables/iptables"
)

type rule_struct struct {
	    IP string
	    Port string
	    Direction string
}

func iptableAdd(w http.ResponseWriter, req *http.Request) {
	ipt, err := iptables.New()
	if err != nil {
		fmt.Fprintf(w, "New failed: %v", err)
		}

	reqBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}

	var rule  rule_struct
	var chain =""

	json.Unmarshal([]byte(reqBody), &rule)
	if rule.Direction == "inbound"{
		chain="INPUT"
	}else{
		chain="OUTPUT"
	}
	if rule.Port == ""{
	err = ipt.Append("filter",chain,"-s",rule.IP,"-j","DROP")
	}else{
	err = ipt.Append("filter",chain,"-p","tcp","-s",rule.IP,"--dport",rule.Port,"-j","DROP")
	}
	if err != nil {
                fmt.Fprintf(w, "New failed: %v", err)
        }

	fmt.Fprintf(w, "Ip address blocked succesfully")

}
