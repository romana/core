package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
)

type IPtables struct {
	Tables []IPtable
}

type IPtable struct {
	Name string
	Chains []IPchain
}

type IPchain struct {
	Name string
	Rules []IPrule
}

type IPrule struct {
	Match []Match
	Action  IPtablesAction
}

type Match struct {
	Negated bool
	Body string
}

type IPtablesAction struct {
	Type string
	Body string
}

type IPtablesComment string

func (i *IPtables) ParseItem(Item) {

}

func main() {
	flag.Parse()

	iptables := IPtables{}

	reader := bufio.NewReader(os.Stdin)
	lexer := NewLexer(reader)

	for {
		item := lexer.NextItem()
		fmt.Printf("Discovered item of type %s with body %s \n", item.Type, item.Body)
		iptables.ParseItem(item)

		if item.Type == itemError || item.Type == itemEOF {
			break
		}
	}
}
