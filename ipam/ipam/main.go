package main

import "fmt"
import "github.com/romanaproject/pani_core/ipam"
import "github.com/romanaproject/pani_core/common"

func main() {
  fmt.Println(common.ImportantUtility())
  fmt.Println("Hello... My address is", ipam.GetAddress)
}