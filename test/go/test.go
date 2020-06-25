package main

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1)/dbname?allowAllFiles=true")
	if err != nil {
		fmt.Println(err)
	}
	db.Exec("SELECT 1;")
}
