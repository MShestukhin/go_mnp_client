package main

import (
	"database/sql"
	"fmt"
	_ "github.com/godror/godror"
	"github.com/miekg/dns"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var file_id int

func thread(con *dns.Conn, rows *sql.Rows, rn int) {

	//make header for SRF standart is RFC 1035, it should be header flags 0x0100
	//##########################################################################################################
	var msisdn string
	m := new(dns.Msg)
	header :=dns.MsgHdr{
		Id:                 0,
		Response:           false,
		Opcode:             0,
		Authoritative:      false,
		Truncated:          false,
		RecursionDesired:   true,
		RecursionAvailable: false,
		Zero:               false,
		AuthenticatedData:  false,
		CheckingDisabled:   false,
		Rcode:              0,
	}
	m.MsgHdr = header

	//start sort through msisdn from db and send to server
	//##########################################################################################################
	//mutex.Lock()
	for rows.Next() {
		if rn != 0 {
			rows.Scan(&file_id,&msisdn,&rn)
		} else {
			rows.Scan(&file_id,&msisdn)
		}
		msisdn_naptr := make([]string, len(msisdn))
		size := len(msisdn)
		// revers msisdn : for example 79834077832 -> 23877043897
		for  i , m := range msisdn {
			msisdn_naptr[(size-1)-i]=string(m)
		}
		// 2.3.8.7.7.0.4.3.8.9.7.e164.arpa. that should be for naptr
		naptr_msisdn := strings.Join(msisdn_naptr, ".")+".e164.arpa."
		m.SetQuestion(naptr_msisdn,  dns.TypeNAPTR)
		time.Sleep(100 * time.Microsecond)
		con.WriteMsg(m)
	}
	log.Println("Send")
	//mutex.Unlock()
}

func pars_answers(push_insert_buf []dns.Msg, r *regexp.Regexp, r_tel *regexp.Regexp, db *sql.DB) {
	log.Println("1000 rows")
	iter :=0
	file_id_buf := make([]int, 1000)
	msisdn_err_buf := make([]string, 1000)
	cod_err_buf := make([]int, 1000)
	cod_str_err_buf := make([]string, 1000)
	log.Println("Non-Validated MSISDN")
	for _, msg := range push_insert_buf {
		if msg.Rcode != 0 {
			log.Println("Rcode error ", msg)
			continue
		}
		//E2U+pstn:tel" "!^.*$!tel:+73422461703;npdi;rn=d2701;rn-context=+7!
		answr := msg.Answer[0].(*dns.NAPTR)
		rn := r.FindStringSubmatch(answr.Regexp)
		if len(rn) < 3 {
			rn_tel := r_tel.FindStringSubmatch(answr.Regexp)
			file_id_buf[iter] = file_id
			msisdn_err_buf[iter] = rn_tel[1]
			cod_err_buf[iter] = 9
			cod_str_err_buf[iter] = "MNP check error"
			iter++
			continue
		}
		if rn[2] != "01" {
			rn_tel := r_tel.FindStringSubmatch(answr.Regexp)
			file_id_buf[iter] = file_id
			msisdn_err_buf[iter] = rn_tel[1]
			cod_err_buf[iter] = 9
			cod_str_err_buf[iter] = "MNP check error"
			iter++
			continue
		}
	}
	log.Println(msisdn_err_buf[0:iter-1])
	if iter !=0 {
		i,err := db.Exec("begin ftp.set_rec_error(:file_id,:msisdn,:res,:err); end;", file_id_buf[0:iter-1], msisdn_err_buf[0:iter-1], cod_err_buf[0:iter-1],cod_str_err_buf[0:iter-1])
		if err !=nil {
			fmt.Println(err.Error())
		}
		num_updated_rows, err := i.RowsAffected()
		log.Println("The number of updated rows %d",num_updated_rows)
	}
}

func thread_dns_serve(con *dns.Conn, ch chan bool,r *regexp.Regexp, r_tel *regexp.Regexp, db *sql.DB, cnt int, timeout time.Duration)  {
	resv_int :=0
	resv_j :=0
	var all_resv int32
	all_resv = 0
	step := 1000
	insert_buf :=make([]dns.Msg,cnt)
	for {
		msg, err := con.ReadMsg()
		if err !=nil { break }
		if resv_int%step == 0 && resv_int !=0 {
			go pars_answers(insert_buf[resv_j*step : resv_j*step +step-1],r, r_tel, db)
			resv_j++
		}
		if resv_j*step == cnt {
			resv_j =0
			resv_int=0
		}
		insert_buf[resv_int] = *msg
		resv_int++
		all_resv++
		con.SetReadDeadline(time.Now().Add(time.Second * timeout))
	}
	//resv_int = resv_int-1
	fmt.Println(resv_int, resv_j , cnt)
	pars_answers(insert_buf[resv_j*step : resv_int],r, r_tel, db)
	log.Println("Numbers recieve msisdn : ",resv_int)
	log.Println("Numbers all msisdn that should check : ", cnt)
	if all_resv == int32(resv_int +1) {
		log.Println("All package recieve")
	} 	else{
		log.Println("Not all package recieve: lose " ,(int32(cnt)-all_resv+1))
	}
	ch<-true
}

func db_mnp_check_thread(i int, ch chan bool, mutex *sync.Mutex,con *dns.Conn,db *sql.DB){
	mutex.Lock()
	dbQuery,err := db.Prepare("select * from (select em.file_id, em.msisdn, rownum rn from FTP_ES_MSISDN em where sync_result=1) where rn > :1 AND rn < :2")
	//dbQuery,err := db.Prepare("select * from (select em.msisdn, rownum rn from ES_MSISDN em WHERE ES_ID = 302) where rn > :1 AND rn < :2")
	if err != nil {
		fmt.Println("Error processing  query")
		fmt.Println(err)
		return
	}
	defer dbQuery.Close()
	rows, err := dbQuery.Query(i*100000, (i+1) * 100000)
	if err != nil {
		fmt.Println("Error running query")
		fmt.Println(err)
		return
	}
	defer rows.Close()
	defer mutex.Unlock()
	thread(con,rows,1)
	ch<-true

}

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
	//config :=new(Config)
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

func main(){

	// create log file
	//##########################################################################################################

	f, err := os.OpenFile(config.logPath, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)
	
	// create db oracle connection
	//##########################################################################################################
	//db, err := sql.Open("godror", "oracle://svcbic:m83hose55tcp@192.168.97.41:1521/sk")
	db, err := sql.Open("godror", "oracle://" + config.usr + ":" +config.pswd +"@"+config.db)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()

	// try to know dns server ip
	//##########################################################################################################
	dns_server_ip ,err := db.Query("select val from SETTINGS where code='mnp_dns_server' and rownum =1")
	//cnt_row,err := db.Query("select COUNT(*) from ES_MSISDN WHERE ES_ID = 302")
	if err != nil {
		fmt.Println("Error running query")
		fmt.Println(err)
		return
	}
	defer dns_server_ip.Close()
	dns_server_ip.Next()
	dns_server_ip.Scan(&config.dns_server_ip)
	log.Println(config.dns_server_ip)
	// count all numbers
	//##########################################################################################################
	var cnt int
	cnt_row,err := db.Query("select COUNT(*) from FTP_ES_MSISDN WHERE sync_result = 1")
	//cnt_row,err := db.Query("select COUNT(*) from ES_MSISDN WHERE ES_ID = 302")
	if err != nil {
		fmt.Println("Error running query")
		fmt.Println(err)
		return
	}
	defer cnt_row.Close()
	cnt_row.Next()
	cnt_row.Scan(&cnt)
	//var rows *sql.Rows
	r, _ := regexp.Compile("rn=d([0-9]{2})([0-9]{2})?")
	r_tel, _ := regexp.Compile("tel:[+](.[0-9]+)?")
	con := new(dns.Conn)
	conn, _ := net.Dial("udp", config.dns_server_ip+":53")
	defer conn.Close()
	con.Conn =conn
	if cnt == 0 {
		log.Println("No data in database for mnp check")
		return
	} else if cnt >100000 {
		// create udp connect to dns host and start listen answers in thread func thread
		//##########################################################################################################
		log.Println("Start long work rows in db : ",cnt)
		server_dns_ch := make(chan bool)
		go thread_dns_serve(con, server_dns_ch,r,r_tel, db, 100000,10)
		i:=0
		ch := make(chan bool)
		var mutex sync.Mutex
		for (i+1)*100000 < cnt {
			for i := 1; i < 3; i++{
				go db_mnp_check_thread(i, ch, &mutex, con, db)
			}
			for i := 1; i < 3; i++{
				<-ch
			}
			i++
		}
		<-server_dns_ch
	} else {
		// read all edd mts msisdn that have sync_result = 1;
		//if sync_result 0 that means msisdn is mts
		//if sync_result 1 that means msisdn add it should be check
		//if sync_result 2 that means msisdn was adding
		//##########################################################################################################
		log.Println("Start work rows in db : ",cnt)
		rows,err := db.Query("select file_id, msisdn from FTP_ES_MSISDN WHERE sync_result = 1")
		if err != nil {
			fmt.Println("Error running query")
			fmt.Println(err)
			return
		}
		defer rows.Close()
		server_dns_ch := make(chan bool)
		go thread_dns_serve(con, server_dns_ch,r,r_tel, db, cnt,2)
		thread(con,rows,0)
		<-server_dns_ch
	}
}
