package main

import (
	"flag"
	"fmt"
	"github.com/romana/core/pkg/util/iptsave"
	"os"
)

func main() {
	flag.Parse()

	ipt := iptsave.IPtables{}
	ipt.Parse(os.Stdin)

	fmt.Println(ipt.Render())
}
