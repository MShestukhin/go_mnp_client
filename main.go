package main

import (
	_ "github.com/godror/godror"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

var file_id int

type Config struct {
	logPath string
	db string
	pswd string
	usr string
	dns_server_ip string
}

var config Config

func init() {
	configFile, err := ioutil.ReadFile("/home/bic/bic-ftp/etc/bic-ftp.conf")
	if err != nil {
		log.Fatal(err)
	}
	configLines := strings.Split(string(configFile), "\n")

	for i := 0; i < len(configLines); i++ {
		if strings.Contains(configLines[i], "log-path"){
			newstr :=strings.Replace(configLines[i], " ", "", -1)
			a:=strings.Split(newstr,"=")
			today := time.Now()
			config.logPath = a[1]+"/"+today.Format("2006.01.02")+".log"
		}
		if strings.Contains(configLines[i], "base"){
			newstr :=strings.Replace(configLines[i], " ", "", -1)
			a:=strings.Split(newstr,"=")
			config.db = a[1]
		}
		if strings.Contains(configLines[i], "user"){
			newstr :=strings.Replace(configLines[i], " ", "", -1)
			a:=strings.Split(newstr,"=")
			config.usr = a[1]
		}
		if strings.Contains(configLines[i], "pswd"){
			newstr :=strings.Replace(configLines[i], " ", "", -1)
			a:=strings.Split(newstr,"=")
			config.pswd = a[1]
		}
	}
}

var err_handler func(err error)

func main() {

	//create log file
	//##########################################################################################################
	f, err := os.OpenFile(config.logPath, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
		return
	}
	defer f.Close()
	log.SetOutput(f)
	var mnp_client *Worker
	err_mnp_check := func(err error) {
		if err != nil {
			log.Println(err)
			mnp_client.disconnect()
			os.Exit(1)
		}
	}
	err_handler = err_mnp_check
	mnp_client = newWorker(config,err_mnp_check)
	mnp_client.process()

}
