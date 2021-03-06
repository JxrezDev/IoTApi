package main

import (
	"github.com/JxrezDev/IoTApi/controller"
	gohandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/register", controller.RegisterHandler).
		Methods("POST")
	r.HandleFunc("/login", controller.LoginHandler).
		Methods("POST")
	r.HandleFunc("/profile", controller.ProfileHandler).
		Methods("GET")
	r.HandleFunc("/authVerification", controller.AuthVerification).
		Methods("POST")
	r.HandleFunc("/banca", controller.BancaHandler).
		Methods("POST")
	r.HandleFunc("/bancas", controller.BancasHandler).
		Methods("GET")

	ch := gohandlers.CORS(gohandlers.AllowedOrigins([]string{"*"}),
		gohandlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
		gohandlers.AllowedMethods([]string{"GET", "POST", "PUT", "OPTIONS"}))

	log.Fatal(http.ListenAndServe(":9001", ch(r)))
}
