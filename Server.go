package main

import (
	"github.com/miekg/dns"
	"log"
	"time"
)

type Server struct {
	con *dns.Conn
	w *Worker
}

func (server *Server) start(cnt int, timeout time.Duration)  {
	server_dns_ch := make(chan bool)
	go server.thread_dns_serve(server_dns_ch, cnt, timeout)
	<-server_dns_ch
}

func (server *Server) thread_dns_serve(ch chan bool, cnt int, timeout time.Duration)  {
	resv_int :=0
	resv_j :=0
	var all_resv uint32
	all_resv = 0
	step := 4000
	insert_buf :=make([]dns.Msg,cnt)
	for {
		msg, err := server.con.ReadMsg()
		if err !=nil { break }
		if resv_int%step == 0 && resv_int !=0 {
			server.w.pars_answers(insert_buf[resv_j*step : resv_j*step +step-1])
			resv_j++
		}
		if resv_j*step == cnt {
			resv_j =0
			resv_int=0
		}
		insert_buf[resv_int] = *msg
		resv_int++
		all_resv++
		server.con.SetReadDeadline(time.Now().Add(time.Second * timeout))
	}
	resv_int = resv_int-1
	server.w.pars_answers(insert_buf[resv_j*step : resv_j*step +step-1])
	log.Println("Numbers recieve msisdn : ",resv_int)
	log.Println("Numbers all msisdn that should check : ", cnt)
	if all_resv == uint32(resv_int +1) {
		log.Println("All package recieve")
	} 	else{
		log.Println("Not all package recieve: lose " ,(uint32(cnt)-all_resv+1))
	}
	ch<-true
}

