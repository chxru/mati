package http

import (
	"fmt"
	"net/http"
)

func initiateEndpoints(router *http.ServeMux) {
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	})
}
