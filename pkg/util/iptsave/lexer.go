// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Provides a Lexer struct that extracts tokens from iptables-save output.
package iptsave

import (
	"bufio"
	"fmt"
	log "github.com/romana/rlog"
	"io"
)

// Lexer extracts iptables lexical items from the input stream.
type Lexer struct {
	input *bufio.Reader
	items chan Item
	state stateFn
}

type stateFn func(*Lexer) stateFn

// Returns new iptables Lexer
func NewLexer(input *bufio.Reader) *Lexer {
	return &Lexer{
		input: input,
		items: make(chan Item, 2),
		state: rootState,
	}
}

// newLexer creates and initializes new Lexer object.
func newLexer(input *bufio.Reader) *Lexer {
	return &Lexer{
		input: input,
		items: make(chan Item, 2),
		state: rootState,
	}
}

// NextItem returns next item from input stream.
func (l *Lexer) NextItem() Item {
	log.Trace(3, "In NextItem()")
	for {
		select {
		case item := <-l.items:
			log.Trace(4, "In NextItem() returning item ", item)
			return item
		default:
			if l.state == nil {
				panic("Lexer failed to process input stream")
			}

			log.Trace(4, "In NextItem(), next state")
			l.state = l.state(l)
		}
	}
}

func (l *Lexer) errorf(format string, args ...interface{}) stateFn {
	l.items <- Item{
		Type: ItemError,
		Body: fmt.Sprintf(format, args...),
	}

	return nil
}

func (l *Lexer) errorEof(message string) stateFn {
	l.items <- Item{
		Type: ItemEOF,
		Body: message,
	}

	return nil
}

const (
	nullByte  byte = 00
	endOfText byte = 03 // Represents EOF
)

// next byte wraps reading from an input and partial error checking
// EOF check still has to be done in state functions
func (l *Lexer) nextByte() byte {
	b, err := l.input.ReadByte()
	if err == io.EOF {
		return endOfText
	}

	if err != nil {
		l.errorf("Error: reading from input %s", err)
		return nullByte
	}

	return b
}

// expect peeks into the input stream and checks if expected string is there.
func (l *Lexer) expect(s string) bool {
	expectLength := len(s)
	res := false

	c, err := l.input.Peek(expectLength)
	if err != nil {
		l.items <- Item{Type: ItemError, Body: "Error: failed to read from stream"}
	}

	if string(c) == s {
		res = true
	}

	return res
}

// accept checks if expected sting in the stream and advances reader if it is
func (l *Lexer) accept(s string) bool {
	if l.expect(s) {
		_, _ = l.input.Discard(len(s)) // can't fail after peek inside expect
		return true
	} else {
		return false
	}
}

// rootState is a state at the beginning of the input and outside of any other state.
func rootState(l *Lexer) stateFn {
	log.Trace(3, "In root state")
	for {
		b := l.nextByte()

		// There are 5 states we can go from root.
		switch string(b) {
		case string(endOfText):
			return l.errorEof("EOF reached in root section")
		case "#":
			log.Trace(4, "In root state, switching into the comment state")
			return stateInComment
		case "*":
			log.Trace(4, "In root state, switching into the table state")
			return stateInTable
		case ":":
			log.Trace(4, "In root state, switching into the chain state")
			return stateInChain
		case "-":
			// Checking one byte ahead of reader to detect "-A"
			if l.accept("A ") {
				log.Trace(4, "In root state, switching into the rule state")
				return stateInRule
			}
		case "C":
			// Whenever we arrive at "C" we need to check if it is a "COMMIT" token.
			if l.accept("OMMIT\n") {
				l.items <- Item{Type: itemCommit, Body: "COMMIT"}
				return rootState
			}
		}
	}
}

// stateInComment consumes entire line.
func stateInComment(l *Lexer) stateFn {
	log.Trace(3, "In comment state")

	item := Item{Type: itemComment}
	for {
		b := l.nextByte()
		c := string(b)

		switch c {
		case string(endOfText):
			return l.errorf("Error: unexpected EOF in comment section")
		case "\n":
			l.items <- item
			log.Trace(4, "In comment state, switching into the root state")
			return rootState
		default:
			item.Body += c
		}
	}
}

// stateInTable consumes entire line.
func stateInTable(l *Lexer) stateFn {
	log.Trace(3, "In table state")

	item := Item{Type: itemTable}
	for {
		b := l.nextByte()
		c := string(b)

		switch c {
		case string(endOfText):
			return l.errorf("Error: unexpected EOF in comment section")
		case "\n":
			l.items <- item
			return rootState
		default:
			item.Body += c
		}
	}
}

// stateInChain consumes chain name and checks for default policy token.
func stateInChain(l *Lexer) stateFn {
	log.Trace(3, "In chain state")

	item := Item{Type: itemChain}
	for {
		b := l.nextByte()
		c := string(b)

		switch c {
		case string(endOfText):
			return l.errorf("Error: unexpected EOF in chain section")
		case " ":
			l.items <- item
			return stateInChainPolicy
		case "\n":
			return l.errorf("Unexpectend end of line in chain state")
		default:
			item.Body += c
		}
	}
}

// stateInChainPolicy consumes chain deafult policy if any.
func stateInChainPolicy(l *Lexer) stateFn {
	log.Trace(3, "In chain policy state")

	item := Item{Type: itemChainPolicy}

	b := l.nextByte()
	c := string(b)

	switch c {
	case string(endOfText):
		return l.errorf("Error: unexpected EOF in chain section")
	case "-":
		item.Body = "-"
		l.items <- item
		_ = l.nextByte() // Discard next space to prevent it from getting captured as counter
		return stateInChainCounter
	case "A":
		if l.accept("CCEPT ") {
			item.Body = "ACCEPT"
			l.items <- item
			return stateInChainCounter
		} else {
			l.items <- Item{Type: ItemError, Body: "Unexpected deafult policy for a chain"}
			return nil
		}
	case "R":
		if l.accept("ETURN ") {
			item.Body = "RETURN"
			l.items <- item
			return stateInChainCounter
		} else {
			l.items <- Item{Type: ItemError, Body: "Unexpected deafult policy for a chain"}
			return nil
		}
	case "D":
		if l.accept("ROP ") {
			item.Body = "DROP"
			l.items <- item
			return stateInChainCounter
		} else {
			l.items <- Item{Type: ItemError, Body: "Unexpected deafult policy for a chain"}
			return nil
		}
	default:
		return l.errorf("Unexpectend end of line in chain state")
	}
}

func stateInChainCounter(l *Lexer) stateFn {
	log.Trace(3, "In chain counter state")

	item := Item{Type: itemChainCounter}
	for {
		b := l.nextByte()
		c := string(b)

		switch c {
		case string(endOfText):
			return l.errorf("Error: unexpected EOF in chain counter section")
		case "\n":
			l.items <- item
			return rootState
		default:
			item.Body += c
		}
	}
}

func stateInRule(l *Lexer) stateFn {
	log.Trace(3, "In rule state")

	item := Item{Type: itemRule}
	for {
		b := l.nextByte()
		c := string(b)

		switch c {
		case string(endOfText):
			return l.errorf("Error: unexpected EOF in rule section")
		case " ":
			l.items <- item
			return stateRuleMatch
		default:
			item.Body += c
		}
	}
}

func stateRuleMatch(l *Lexer) stateFn {
	log.Trace(3, "In rule match state")
	var exMarkConsumed, matchLiteralConsumed bool

	item := Item{Type: itemRuleMatch}
	for {
		b := l.nextByte()
		c := string(b)

		log.Trace(4, "In rule match with char ", c)

		switch c {
		case string(endOfText):
			return l.errorf("Error: unexpected EOF in rule section")
		case "!":
			// exclamation mark can appear only once per match
			// and only before match literal
			if exMarkConsumed == true {
				return l.errorf("Unexpected ! in rules spec")
			}

			if matchLiteralConsumed {
				l.items <- item

				// put current '!' back into stream for the next iteration
				// can not fail
				_ = l.input.UnreadByte()

				return stateRuleMatch
			}

			exMarkConsumed = true
			item.Body += c
		case "-":
			// '-' dash can appear in 4 cases
			// in module literal like '-p' or '-m'
			// in module opts like '--dport'
			// in inside opts literal like '--to-destination' or inside body '-j MY-CHAIN'
			// in action '-j'
			onLiteral := false

			if l.expect("p ") || l.expect("m ") || l.expect("i ") || l.expect("o ") || l.expect("s ") || l.expect("d ") {
				// Single dash, single char and a space indicate module literal.
				onLiteral = true

			} else if l.expect("-") {
				// double dash indicate module opts
				// nothing to do, just let it be consumed
			} else if l.accept("j ") {
				l.items <- item
				return stateInRuleAction
			} // any other dash is inside a body

			if onLiteral {
				if matchLiteralConsumed {
					l.items <- item

					// put current '-' back into stream for the next iteration
					// can not fail
					_ = l.input.UnreadByte()

					return stateRuleMatch
				} else {
					matchLiteralConsumed = true
				}
			}

			item.Body += c

		default:
			item.Body += c
		}
	}
}

func stateInRuleAction(l *Lexer) stateFn {
	log.Trace(3, "In rule action state")

	item := Item{Type: itemAction}
	for {
		b := l.nextByte()

		c := string(b)

		switch c {
		case string(endOfText):
			// Rule action is one of the places where
			// we can accept EOF. This is only legal when
			// single rule is being parsed.
			l.items <- item
			return l.errorEof("EOF reached in rule action section")
		case "\n":
			l.items <- item
			return rootState
		default:
			item.Body += c
		}
	}
}
