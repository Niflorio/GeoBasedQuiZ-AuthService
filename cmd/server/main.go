package main

import (
	"fmt"
	"net/http"
)

func welcomeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to my microservice!")
}

func main() {
	http.HandleFunc("/", welcomeHandler)
	http.ListenAndServe(":9000", nil)
}
