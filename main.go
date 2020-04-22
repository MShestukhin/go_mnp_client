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

//func thread(con *dns.Conn, rows *sql.Rows, rn int) {
//
//	//make header for SRF standart is RFC 1035, it should be header flags 0x0100
//	//##########################################################################################################
//	var msisdn string
//	m := new(dns.Msg)
//	header :=dns.MsgHdr{
//		Id:                 0,
//		Response:           false,
//		Opcode:             0,
//		Authoritative:      false,
//		Truncated:          false,
//		RecursionDesired:   true,
//		RecursionAvailable: false,
//		Zero:               false,
//		AuthenticatedData:  false,
//		CheckingDisabled:   false,
//		Rcode:              0,
//	}
//	m.MsgHdr = header
//
//	//start sort through msisdn from db and send to server
//	//##########################################################################################################
//	//mutex.Lock()
//	for rows.Next() {
//		if rn != 0 {
//			rows.Scan(&file_id,&msisdn,&rn)
//		} else {
//			rows.Scan(&file_id,&msisdn)
//		}
//		msisdn_naptr := make([]string, len(msisdn))
//		size := len(msisdn)
//		// revers msisdn : for example 79834077832 -> 23877043897
//		for  i , m := range msisdn {
//			msisdn_naptr[(size-1)-i]=string(m)
//		}
//		// 2.3.8.7.7.0.4.3.8.9.7.e164.arpa. that should be for naptr
//		naptr_msisdn := strings.Join(msisdn_naptr, ".")+".e164.arpa."
//		m.SetQuestion(naptr_msisdn,  dns.TypeNAPTR)
//		time.Sleep(100 * time.Microsecond)
//		con.WriteMsg(m)
//	}
//	log.Println("Send")
//	//mutex.Unlock()
//}
//
//func pars_answers(push_insert_buf []dns.Msg, db *DB_client) {
//	log.Println("1000 rows")
//	iter :=0
//	r, _ := regexp.Compile("rn=d([0-9]{2})([0-9]{2})?")
//	r_tel, _ := regexp.Compile("tel:[+](.[0-9]+)?")
//	file_id_buf := make([]int, 1000)
//	msisdn_err_buf := make([]string, 1000)
//	cod_err_buf := make([]int, 1000)
//	cod_str_err_buf := make([]string, 1000)
//	log.Println("Non-Validated MSISDN")
//	for _, msg := range push_insert_buf {
//		if msg.Rcode != 0 {
//			log.Println("Rcode error ", msg)
//			continue
//		}
//		//E2U+pstn:tel" "!^.*$!tel:+73422461703;npdi;rn=d2701;rn-context=+7!
//		answr := msg.Answer[0].(*dns.NAPTR)
//		rn := r.FindStringSubmatch(answr.Regexp)
//		if len(rn) < 3 {
//			rn_tel := r_tel.FindStringSubmatch(answr.Regexp)
//			file_id_buf[iter] = file_id
//			msisdn_err_buf[iter] = rn_tel[1]
//			cod_err_buf[iter] = 9
//			cod_str_err_buf[iter] = "MNP check error"
//			iter++
//			continue
//		}
//		if rn[2] != "01" {
//			rn_tel := r_tel.FindStringSubmatch(answr.Regexp)
//			file_id_buf[iter] = file_id
//			msisdn_err_buf[iter] = rn_tel[1]
//			cod_err_buf[iter] = 9
//			cod_str_err_buf[iter] = "MNP check error"
//			iter++
//			continue
//		}
//	}
//	log.Println(msisdn_err_buf[0:iter-1])
//	if iter !=0 {
//		num_updated_rows := db.update_msisdn(file_id_buf[0:iter-1], msisdn_err_buf[0:iter-1], cod_err_buf[0:iter-1],cod_str_err_buf[0:iter-1])
//		log.Println("The number of updated rows %d",num_updated_rows)
//	}
//}
//
//func thread_dns_serve(con *dns.Conn, ch chan bool, db *DB_client, cnt int, timeout time.Duration)  {
//	resv_int :=0
//	resv_j :=0
//	var all_resv uint32
//	all_resv = 0
//	step := 1000
//	insert_buf :=make([]dns.Msg,cnt)
//	for {
//		msg, err := con.ReadMsg()
//		if err !=nil { break }
//		if resv_int%step == 0 && resv_int !=0 {
//			go pars_answers(insert_buf[resv_j*step : resv_j*step +step-1], db)
//			resv_j++
//		}
//		if resv_j*step == cnt {
//			resv_j =0
//			resv_int=0
//		}
//		insert_buf[resv_int] = *msg
//		resv_int++
//		all_resv++
//		con.SetReadDeadline(time.Now().Add(time.Second * timeout))
//	}
//	//resv_int = resv_int-1
//	fmt.Println(resv_int, resv_j , cnt)
//	pars_answers(insert_buf[resv_j*step : resv_int], db)
//	log.Println("Numbers recieve msisdn : ",resv_int)
//	log.Println("Numbers all msisdn that should check : ", cnt)
//	if all_resv == uint32(resv_int +1) {
//		log.Println("All package recieve")
//	} 	else{
//		log.Println("Not all package recieve: lose " ,(uint32(cnt)-all_resv+1))
//	}
//	ch<-true
//}
//
//func db_mnp_check_thread(i int, ch chan bool, mutex *sync.Mutex,con *dns.Conn,db *DB_client){
//	mutex.Lock()
//	rows := db.chank_qwery(i*100000,(i+1) * 100000)
//	defer mutex.Unlock()
//	thread(con,rows,1)
//	ch<-true
//
//}

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

var err_handler func(err error)

func main(){

	// create log file
	//##########################################################################################################

	//f, err := os.OpenFile(config.logPath, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	//if err != nil {
	//	log.Fatalf("error opening file: %v", err)
	//	return
	//}
	//defer f.Close()
	//log.SetOutput(f)

	err_mnp_check := func(err error) {
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
	}
	err_handler = err_mnp_check

	mnp_client := newWorker(config,err_mnp_check)
	mnp_client.process()

	//// create db oracle connection
	////##########################################################################################################
	//db, err:= newDB(config)
	//if err != nil {
	//	return
	//}
	//// try to know dns server ip
	////##########################################################################################################
	//config.dns_server_ip = db.get_dns_ip()
	//log.Println(config.dns_server_ip)
	//
	//// count all numbers
	////##########################################################################################################
	//cnt := db.get_cnt()
	//
	//conn, _ := net.Dial("udp", config.dns_server_ip+":53")
	//con := new(dns.Conn)
	//defer conn.Close()
	//con.Conn =conn
	//
	//if cnt == 0 {
	//	log.Println("No data in database for mnp check")
	//	return
	//} else if cnt >100000 {
	//	// create udp connect to dns host and start listen answers in thread func thread
	//	//##########################################################################################################
	//	log.Println("Start long work rows in db : ",cnt)
	//	server_dns_ch := make(chan bool)
	//	go thread_dns_serve(con, server_dns_ch, db, 100000,10)
	//	i:=0
	//	ch := make(chan bool)
	//	var mutex sync.Mutex
	//	for (i+1)*100000 < cnt {
	//		for i := 1; i < 3; i++{
	//			go db_mnp_check_thread(i, ch, &mutex, con, db)
	//		}
	//		for i := 1; i < 3; i++{
	//			<-ch
	//		}
	//		i++
	//	}
	//	<-server_dns_ch
	//} else {
	//	// read all edd mts msisdn that have sync_result = 1;
	//	//if sync_result 0 that means msisdn is mts
	//	//if sync_result 1 that means msisdn add it should be check
	//	//if sync_result 2 that means msisdn was adding
	//	//##########################################################################################################
	//	log.Println("Start work rows in db : ",cnt)
	//	rows := db.get_msisdns()
	//	server_dns_ch := make(chan bool)
	//	go thread_dns_serve(con, server_dns_ch, db, cnt,2)
	//	client := Client{con:con}
	//	client.sendAll(rows,0)
	//	//thread(con,rows,0)
	//	<-server_dns_ch
	//}
}
