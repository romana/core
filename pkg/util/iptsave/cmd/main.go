package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
_	"encoding/json"
	"github.com/romana/core/pkg/util/iptsave"
)

func main() {
	flag.Parse()

	ipt := iptsave.IPtables{}

	reader := bufio.NewReader(os.Stdin)
	lexer := iptsave.NewLexer(reader)
	ipt.Parse(lexer)

/*
	for {
		item := lexer.NextItem()
		// fmt.Printf("Discovered item of type %s with body %s \n", item.Type, item.Body)
		ipt.ParseItem(item)

		if item.Type == iptsave.ItemError || item.Type == iptsave.ItemEOF {
			break
		}
	}
*/

/*
	if b, err := json.Marshal(ipt); err != nil {
		fmt.Printf("%s", err)
	} else {
		fmt.Printf("%s", b)
	}
*/


	fmt.Println(ipt.Render())
}
