package agent

// Web requests handling.

import (
	"log"
	"net/http"
)

// Serve pani agent API.
func (a Agent) Serve() {
	http.HandleFunc("/", a.interfaceHandler)
	log.Fatal(http.ListenAndServe(":8899", nil))
}
