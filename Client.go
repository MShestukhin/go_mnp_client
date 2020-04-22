package main

import (
	"database/sql"
	"github.com/miekg/dns"
	"log"
	"strings"
	"time"
)

type Client struct {
	con *dns.Conn
}

func (client *Client) sendAll (rows *sql.Rows, rn int) {

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
		client.con.WriteMsg(m)
	}
	log.Println("Send")
	//mutex.Unlock()
}
