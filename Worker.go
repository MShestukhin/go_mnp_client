package main

import (
	"github.com/miekg/dns"
	"log"
	"net"
	"regexp"
	"sync"
)

type Worker struct {
		db *DB_client
		server *Server
		client *Client
		cnt int
}

func newWorker(config Config, err_mnp_check func(err error)) *Worker {
	w := new(Worker)
	// create db oracle connection
	//##########################################################################################################
	db, err:= newDB(&config)
	err_mnp_check(err)
	w.db = db

	// try to know dns server ip and connect to
	//##########################################################################################################
	config.dns_server_ip = w.db.get_dns_ip()

	conn, err := net.Dial("udp", config.dns_server_ip+":53")
	err_mnp_check(err)

	con := new(dns.Conn)
	defer conn.Close()
	con.Conn =conn

	// count all numbers
	//##########################################################################################################
	cnt := db.get_cnt()
	w.server.con = con
	w.server.w = w
	w.client.con = con
	w.cnt = cnt
	return w
}

func (w * Worker) disconnect() {
	w.db.db.Close()
	w.server.con.Close()
}

func (w * Worker) process() {
	if w.cnt >100000 {
		w.server.start(w.cnt,5)
		w.long_road_process()
	} else {
		rows := w.db.get_msisdns()
		w.server.start(w.cnt,2)
		w.client.sendAll(rows,0)
	}
}

func (w * Worker) db_mnp_check_thread(i int, ch chan bool, mutex *sync.Mutex) {
	mutex.Lock()
	rows := w.db.chank_qwery(i*100000,(i+1) * 100000)
	defer mutex.Unlock()
	w.client.sendAll(rows,1)
	ch<-true

}

func (w * Worker) long_road_process() {
	i:=0
	ch := make(chan bool)
	var mutex sync.Mutex
	for (i+1)*100000 < w.cnt {
		for i := 1; i < 3; i++{
			go w.db_mnp_check_thread(i, ch, &mutex)
		}
		for i := 1; i < 3; i++{
			<-ch
		}
		i++
	}
}

func (w *Worker)pars_answers(push_insert_buf []dns.Msg) {
	log.Println("4000 rows")
	iter :=0
	r, _ := regexp.Compile("rn=d([0-9]{2})([0-9]{2})?")
	r_tel, _ := regexp.Compile("tel:[+](.[0-9]+)?")
	file_id_buf := make([]int, 4000)
	msisdn_err_buf := make([]string, 4000)
	cod_err_buf := make([]int, 4000)
	cod_str_err_buf := make([]string, 4000)
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
		num_updated_rows := w.db.update_msisdn(file_id_buf[0:iter-1], msisdn_err_buf[0:iter-1], cod_err_buf[0:iter-1],cod_str_err_buf[0:iter-1])
		log.Println("The number of updated rows %d",num_updated_rows)
	}
}
