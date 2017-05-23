package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/romana/core/agent/iptsave"
)

func main() {
	flag.Parse()

	ipt := iptsave.IPtables{}
	ipt.Parse(os.Stdin)

	fmt.Println(ipt.Render())
}
