package main

import (
    "fmt"
    "github.com/romanaproject/pani_core/ipam"
    "github.com/romanaproject/pani_core/common"
    "database/sql"
    "github.com/go-sql-driver/mysql"
)

func main() {
  fmt.Println(common.ImportantUtility())
  s, err :=  sql.Open("mysql", "user:password@/dbname")
  s.Close()	
  ns := new(mysql.NullTime)
  fmt.Println(ns)
  fmt.Println("Of course opening mysql will fail: ",err)
  fmt.Println("Hello... My address is", ipam.GetAddress)
}