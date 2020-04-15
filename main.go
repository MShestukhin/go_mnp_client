package main

import (
	"database/sql"
	"fmt"
	_ "github.com/godror/godror"
	"github.com/miekg/dns"
	"log"
	"net"
	"regexp"
	"strings"
	"time"
	"sync"
	//"os"
)

var file_id int

func thread(con *dns.Conn, rows *sql.Rows) {

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
		rows.Scan(&msisdn,&file_id)
		//rows.Scan(&msisdn)
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
	//file_id_buf := make([]int, 1000)
	//msisdn_err_buf := make([]string, 1000)
	//cod_err_buf := make([]int, 1000)
	//cod_str_err_buf := make([]string, 1000)
	log.Println("Non-Validated MSISDN")
	for _, msg := range push_insert_buf {
		if msg.Rcode != 0 {
			log.Println("err")
			log.Println("err")
			//answr := msg.Answer[0].(*dns.NAPTR)
			//rn_tel := r_tel.FindStringSubmatch(answr.Regexp)
			//file_id_buf[iter] = file_id
			//log.Println(rn_tel[1])
			//msisdn_err_buf[iter] = rn_tel[1]
			//cod_err_buf[iter] = 8
			//cod_str_err_buf[iter] = "MNP check error"
			//iter++
			continue
		}
		//E2U+pstn:tel" "!^.*$!tel:+73422461703;npdi;rn=d2701;rn-context=+7!
		answr := msg.Answer[0].(*dns.NAPTR)
		rn := r.FindStringSubmatch(answr.Regexp)
		if len(rn) < 2 {
			//rn_tel := r_tel.FindStringSubmatch(answr.Regexp)
			//file_id_buf[iter] = file_id
			//fmt.Println(rn_tel[1])
			//log.Println(rn_tel[1])
			//msisdn_err_buf[iter] = rn_tel[1]
			//cod_err_buf[iter] = 9
			//cod_str_err_buf[iter] = "MNP check error"
			iter++
			continue
		}
		if rn[2] != "01" {
			rn_tel := r_tel.FindStringSubmatch(answr.Regexp)
			//file_id_buf[iter] = file_id
			fmt.Println(rn_tel[1])
			//log.Println(rn_tel[1])
			//msisdn_err_buf[iter] = rn_tel[1]
			//cod_err_buf[iter] = 9
			//cod_str_err_buf[iter] = "MNP check error"
			iter++
			continue
		}
	}
	//if iter !=0 {
	//	i,err := db.Exec("begin ftp.set_rec_error(:file_id,:msisdn,:res,:err); end;", file_id_buf[0:iter-1], msisdn_err_buf[0:iter-1], cod_err_buf[0:iter-1],cod_str_err_buf[0:iter-1])
	//	if err !=nil {
	//		fmt.Println(err.Error())
	//	}
	//	num_updated_rows, err := i.RowsAffected()
	//	log.Println("The number of updated rows %d",num_updated_rows)
	//}
}

func thread_dns_serve(con *dns.Conn, ch chan bool,r *regexp.Regexp, r_tel *regexp.Regexp, db *sql.DB, cnt int)  {
	resv_int :=0
	resv_j :=0
	all_resv :=0
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
		con.SetReadDeadline(time.Now().Add(time.Second * 10))
	}
	resv_int = resv_int-1
	log.Println("Numbers recieve msisdn : %d",resv_int)
	log.Println("Numbers all msisdn that should check : %d", cnt)
	pars_answers(insert_buf[resv_j*step : resv_int],r, r_tel, db)
	if all_resv == resv_int +1 {
		log.Println("All package recieve")
	} 	else{
		log.Println("Not all package recieve: lose %d" ,(cnt-all_resv+1))
	}
	ch<-true
}

func db_mnp_check_thread(i int, ch chan bool, mutex *sync.Mutex,con *dns.Conn,db *sql.DB){
	//dbQuery,err := db.Prepare("select * from (select em.*, rownum rn from FTP_ES_MSISDN em where sync_result=1) where rn > :1 AND rn < :2")
	mutex.Lock()
	dbQuery,err := db.Prepare("select * from (select em.msisdn, rownum rn from ES_MSISDN em WHERE ES_ID = 302) where rn > :1 AND rn < :2")
	if err != nil {
		fmt.Println("Error running query")
		fmt.Println(err)
		return
	}
	//defer dbQuery.Close()
	rows, err := dbQuery.Query(i*10000, (i+1) * 10000)
	if err != nil {
		fmt.Println(".....Error processing query")
		fmt.Println(err)
		return
	}
	mutex.Unlock()
	//defer rows.Close()
	thread(con,rows)
	err_p:=dbQuery.Close()
	if err_p != nil {
		log.Println("Can not finish prepare")
		log.Println(err)
	}
	err =rows.Close()
	if err != nil {
		log.Println(err)
		log.Println("Can not finish qwery")
	}

}

func main(){

	// create log file
	//##########################################################################################################
	//f, err := os.OpenFile("/home/bic/bic-ftp/log/15.04.2020.log", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	//if err != nil {
	//	log.Fatalf("error opening file: %v", err)
	//}
	//defer f.Close()
	//
	//log.SetOutput(f)

	// create db oracle connection
	//##########################################################################################################
	db, err := sql.Open("godror", "oracle://svcbic:m83hose55tcp@192.168.97.41:1521/sk")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()

	// cnt for array
	//##########################################################################################################
	var cnt int
	//cnt_row,err := db.Query("select COUNT(*) from FTP_ES_MSISDN WHERE sync_result = 1")
	cnt_row,err := db.Query("select COUNT(*) from ES_MSISDN WHERE ES_ID = 302")
	if err != nil {
		fmt.Println("Error running query")
		fmt.Println(err)
		return
	}
	defer cnt_row.Close()
	cnt_row.Next()
	cnt_row.Scan(&cnt)
	//var rows *sql.Rows
	r, _ := regexp.Compile("rn=d(.[1-9]+)(.[0-9]+)?")
	r_tel, _ := regexp.Compile("tel:[+](.[0-9]+)?")
	con := new(dns.Conn)
	conn, _ := net.Dial("udp", "10.241.30.171:53")
	defer conn.Close()
	con.Conn =conn
	if cnt == 0 {
		log.Println("No data in database for mnp check")
		return
	} else if cnt >10000 {
		// create udp connect to dns host and start listen answers in thread func thread
		//##########################################################################################################
		log.Println("Start long work rows in db : ",cnt)
		server_dns_ch := make(chan bool)
		go thread_dns_serve(con, server_dns_ch,r,r_tel, db, 10000)
		i:=0
		ch := make(chan bool)
		var mutex sync.Mutex
		for (i+1)*10000 < cnt {
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
		log.Println("Start work rows in db : %d",cnt)
		rows,err := db.Query("select file_id, msisdn from FTP_ES_MSISDN WHERE sync_result = 1")
		if err != nil {
			fmt.Println("Error running query")
			fmt.Println(err)
			return
		}
		defer rows.Close()
		server_dns_ch := make(chan bool)
		go thread_dns_serve(con, server_dns_ch,r,r_tel, db, cnt)
		go thread(con,rows)
		<-server_dns_ch
	}
}
