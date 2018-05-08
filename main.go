package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
)

type (
	routeSet []route
	route    struct {
		Name        string
		Method      string
		Patter      string
		HandlerFunc http.HandlerFunc
	}
	creds struct {
		Username string
		Password string
		Submit   string
	}

	project struct {
		DocumentSelfLink string `json:"documentSelfLink"`
		Name             string
		Roles            []string
		CustomProperties interface{} `json:"customProperties"`
	}
	user struct {
		Roles    []string
		Projects []project
		ID       string
		Name     string
		Email    string
		Type     string
	}
)

var routes = routeSet{
	route{"Admiral User Manager", "GET", "/", home},
	route{"Admiral User Login", "GET", "/login", login},
	route{"Auth", "POST", "/auth", auth},
	route{"Admiral Logout", "GET", "/logout", logout},
	route{"Users", "GET", "/user", listUsers},
}

func admiralEndpoint() string {
	admiralEndpoint := os.Getenv("ADMIRAL_ENDPOINT")
	if admiralEndpoint != "" {
		return admiralEndpoint
	}
	return "http://admiral:8282"
}

func newRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)

	for _, route := range routes {
		var handler http.Handler
		handler = route.HandlerFunc
		handler = logger(handler, route.Name)

		router.
			Methods(route.Method).
			Path(route.Patter).
			Name(route.Name).
			Handler(handler)
	}
	return router
}

func logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		inner.ServeHTTP(w, r)

		log.Printf(
			"%s\t%s\t%s\t%s",
			r.Method,
			r.RequestURI,
			name,
			time.Since(start),
		)
	})
}

func checkSession(w http.ResponseWriter, r *http.Request) {
	success, err := getSession(r)
	if err != nil {
		fmt.Println("Error validating session")
		w.WriteHeader(500)
		fmt.Fprint(w, "Error Validating Session")
		return
	}
	if !success {
		fmt.Println("Session invalid. Redirecting to login")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
	} else {
		fmt.Println("Session valid")
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	checkSession(w, r)
	f, _ := ioutil.ReadFile("views/index.html")
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", f)
}

func getSession(r *http.Request) (bool, error) {
	url := admiralEndpoint() + "/auth/session"
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating the request")
		fmt.Println(err)
		return false, err
	}
	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}
	response, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return false, err
	}
	if response.StatusCode == 200 {
		return true, nil
	}
	return false, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	f, _ := ioutil.ReadFile("views/login.html")
	fmt.Fprintf(w, "%s", f)
}

func logout(w http.ResponseWriter, r *http.Request) {
	url := admiralEndpoint() + "/auth/session"
	client := &http.Client{}
	req, _ := http.NewRequest("DELETE", url, nil)
	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}
	_, err := client.Do(req)
	if err != nil {
		w.WriteHeader(500)
		fmt.Println("Error signing out")
		return
	}
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func auth(w http.ResponseWriter, r *http.Request) {
	e := new(creds)
	err := r.ParseForm()
	if err != nil {
		fmt.Println("parse error")
		fmt.Println(err)
	}
	decoder := schema.NewDecoder()
	err = decoder.Decode(e, r.Form)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		fmt.Fprint(w, err)
		return
	}
	token, success := getCookie(*e)
	if !success {
		fmt.Println(err)
		w.WriteHeader(500)
		fmt.Fprint(w, err)
		return
	}
	w.Header().Set("Set-Cookie", token)
	http.Redirect(w, r, "/", http.StatusMovedPermanently)
}

func getCookie(creds creds) (string, bool) {
	url := admiralEndpoint() + "/core/authn/basic"
	client := &http.Client{}
	b := []byte(`{"requestType":"LOGIN"}`)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(b))
	if err != nil {
		fmt.Println("Error creating the request")
		fmt.Println(err)
		return "", false
	}
	req.SetBasicAuth(creds.Username, creds.Password)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return "", false
	}
	cookie := response.Header.Get("Set-Cookie")
	return cookie, true
}

func listUsers(w http.ResponseWriter, r *http.Request) {
	checkSession(w, r)
	url := admiralEndpoint() + "/auth/idm/principals?criteria=*&roles=all"
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating the request")
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}
	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}
	response, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		fmt.Fprint(w, "Error Getting Users")
		w.WriteHeader(500)
		return
	}
	userList := []user{}
	temp, _ := ioutil.ReadAll(response.Body)
	err = json.Unmarshal(temp, &userList)
	if err != nil {
		fmt.Println("There was an error:", err)
		w.WriteHeader(500)
		fmt.Fprint(w, "Error Getting Users")
		return
	}
	t, parseError := template.ParseFiles("views/users.html")
	if parseError != nil {
		fmt.Println(parseError)
	}
	var b bytes.Buffer
	parseError = t.Execute(&b, userList)
	if parseError != nil {
		fmt.Println(parseError)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", b.String())
}

func main() {
	router := newRouter()
	router.PathPrefix("/assets").Handler(http.StripPrefix("/assets", http.FileServer(http.Dir("views/assets/"))))
	fmt.Println("Listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
