package probes

import "net/http"

func MakeReadyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"status\": \"OK\"}"))
	})
}

func MakeLiveHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"status\": \"OK\"}"))
	})
}
