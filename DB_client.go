package main

import (
	"database/sql"
	_ "github.com/godror/godror"
	"log"
)

type DB_client struct {
	db * sql.DB
}

func (dbase *DB_client) qwery(qwrt string) (*sql.Rows, int) {
	rows,err := dbase.db.Query(qwrt)
	err_handler(err)
	defer rows.Close()
	return rows, 0
}

func (dbase *DB_client) get_cnt() int {
	cnt :=0
	cnt_qwery, _ := dbase.qwery("select COUNT(*) from FTP_ES_MSISDN WHERE sync_result = 1")
	cnt_qwery.Next()
	cnt_qwery.Scan(&cnt)
	return cnt
}

func (dbase *DB_client) get_dns_ip() string {
	var msisdn string
	msisdn_qwery, _ := dbase.qwery("select val from SETTINGS where code='mnp_dns_server' and rownum =1")
	msisdn_qwery.Next()
	msisdn_qwery.Scan(&msisdn)
	return msisdn
}

func (dbase *DB_client) get_msisdns() *sql.Rows {
	msisdns_qwery, _ := dbase.qwery("select file_id, msisdn from FTP_ES_MSISDN WHERE sync_result = 1")
	return msisdns_qwery
}

func (dbase *DB_client) update_msisdn(file_id_buf []int, msisdn_err_buf []string, cod_err_buf []int, cod_str_err_buf []string) int64 {
	i,err := dbase.db.Exec("begin ftp.set_rec_error(:file_id,:msisdn,:res,:err); end;", file_id_buf, msisdn_err_buf, cod_err_buf,cod_str_err_buf)
	err_handler(err)
	num_updated_rows, err := i.RowsAffected()
	log.Println("The number of updated rows %d",num_updated_rows)
	return num_updated_rows
}

func (dbase *DB_client) chank_qwery(first int, end int) *sql.Rows {

	dbQuery,err := dbase.db.Prepare("select * from (select em.file_id, em.msisdn, rownum rn from FTP_ES_MSISDN em where sync_result=1) where rn > :1 AND rn < :2")
	//dbQuery,err := db.Prepare("select * from (select em.msisdn, rownum rn from ES_MSISDN em WHERE ES_ID = 302) where rn > :1 AND rn < :2")
	err_handler(err)
	defer dbQuery.Close()

	rows, err := dbQuery.Query(first, end)
	err_handler(err)
	defer rows.Close()
	return rows
}

func newDB(cgf *Config) (*DB_client, error) {
	dbc := new(DB_client)
	db, err := sql.Open("godror", "oracle://" + cgf.usr + ":" +cgf.pswd +"@"+cgf.db)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	dbc.db = db
	return dbc, nil
}
