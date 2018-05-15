package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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
	newUser struct {
		Username string
		Password string
		Confirm  string
		IsAdmin  string `json:"isAdmin"`
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
	alert struct {
		Type    string
		Message string
	}
)

var alertColor = map[string]string{
	"OK":  "#4CAF50",
	"ERR": "#f44336",
}

var routes = routeSet{
	route{"Admiral User Manager", "GET", "/", home},
	route{"Admiral User Login", "GET", "/login", login},
	route{"Auth", "POST", "/auth", auth},
	route{"Admiral Logout", "GET", "/logout", logout},
	route{"Users", "GET", "/user", listUsers},
	route{"Delete User", "GET", "/deleteuser/{id}", deleteUser},
	route{"Create User Form", "GET", "/createuser", createUser},
	route{"Create User POST", "POST", "/create", create},
	route{"Non-Admin User", "GET", "/nonadmin", nonAdmin},
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
	switch success {
	case "none":
		fmt.Println("Session invalid. Redirecting to login")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
	case "non-admin":
		fmt.Println("Authenticated as a non-admin user")
		http.Redirect(w, r, "/nonadmin", http.StatusTemporaryRedirect)
	}

	fmt.Println("Session valid")
}

func home(w http.ResponseWriter, r *http.Request) {
	homeWithAlert(w, r, alert{})
}

func homeWithAlert(w http.ResponseWriter, r *http.Request, a alert) {
	checkSession(w, r)

	t, parseError := template.ParseFiles("views/index.html")
	if parseError != nil {
		fmt.Println(parseError)
	}
	var b bytes.Buffer
	parseError = t.Execute(&b, a)
	if parseError != nil {
		fmt.Println(parseError)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", b.String())
}

func getSession(r *http.Request) (string, error) {
	none := "none"
	url := admiralEndpoint() + "/auth/session"
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating the request")
		fmt.Println(err)
		return none, err
	}
	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}
	response, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return none, err
	}
	if response.StatusCode == 200 {
		u := user{}
		temp, _ := ioutil.ReadAll(response.Body)
		err = json.Unmarshal(temp, &u)
		if err != nil {
			fmt.Println(err)
			return none, err
		}
		admin := checkForAdmin(u)
		if !admin {
			return "non-admin", nil
		}
		return "admin", nil
	}
	return none, nil
}

func checkForAdmin(u user) bool {
	for _, role := range u.Roles {
		if role == "CLOUD_ADMIN" {
			return true
		}
	}
	return false
}

func login(w http.ResponseWriter, r *http.Request) {
	f, _ := ioutil.ReadFile("views/login.html")
	fmt.Fprintf(w, "%s", f)
}

func logout(w http.ResponseWriter, r *http.Request) {
	url := admiralEndpoint() + "/auth/session/logout"
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}
	response, err := client.Do(req)
	if err != nil {
		w.WriteHeader(500)
		fmt.Println("Error signing out")
		return
	}
	cookie := response.Header.Get("set-cookie")
	w.Header().Set("Set-Cookie", cookie)
	login(w, r)
}

func nonAdmin(w http.ResponseWriter, r *http.Request) {
	f, _ := ioutil.ReadFile("views/nonadmin.html")
	fmt.Fprintf(w, "%s", f)
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
	fmt.Println("Successfully logged in as: " + creds.Username)
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

func deleteUser(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	checkSession(w, r)
	client := &http.Client{}
	query := fmt.Sprintf("$filter=id eq '%s'", id)
	userURL := fmt.Sprintf("%s/auth/idm/local/principals?%s", admiralEndpoint(), url.QueryEscape(query))
	userReq, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		fmt.Printf("Error unmarshalling userData: %v", err)
		w.WriteHeader(500)
		return
	}
	for _, cookie := range r.Cookies() {
		userReq.AddCookie(cookie)
	}
	userResponse, err := client.Do(userReq)
	if err != nil {
		w.WriteHeader(500)
		fmt.Println("Error getting User")
		return
	}
	temp, _ := ioutil.ReadAll(userResponse.Body)
	var userData interface{}
	if err = json.Unmarshal(temp, &userData); err != nil {
		fmt.Printf("Error unmarshalling userData: %v", err)
		w.WriteHeader(500)
		return
	}
	documentLinks := userData.(map[string]interface{})["documentLinks"]
	var linkPath string
	for _, link := range documentLinks.([]interface{}) {
		linkPath = link.(string)
	}

	url := fmt.Sprintf("%s%s", admiralEndpoint(), linkPath)
	jsonData := map[string]interface{}{
		"email": id,
		"documentExpirationTimeMicros": 1,
	}
	jsonValue, _ := json.Marshal(jsonData)
	req, _ := http.NewRequest("PUT", url, bytes.NewBuffer(jsonValue))
	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}
	response, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error removing user: %v", err)
		w.WriteHeader(500)
		return
	}
	if response.StatusCode != 200 {
		fmt.Printf("Error removing user: %v", err)
		w.WriteHeader(500)
		return
	}
	a := alert{
		Type:    alertColor["OK"],
		Message: "User: " + id + " successfully deleted.",
	}
	homeWithAlert(w, r, a)
}

func createUser(w http.ResponseWriter, r *http.Request) {
	checkSession(w, r)
	f, _ := ioutil.ReadFile("views/createuser.html")
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", f)
}

func create(w http.ResponseWriter, r *http.Request) {
	checkSession(w, r)
	fData := new(newUser)
	err := r.ParseForm()
	if err != nil {
		fmt.Println("parse error")
		fmt.Println(err)
	}
	decoder := schema.NewDecoder()
	err = decoder.Decode(fData, r.Form)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprint(w, err)
		return
	}

	url := admiralEndpoint() + "/auth/idm/local/principals"
	client := &http.Client{}
	jsonData := map[string]string{
		"email":    fData.Username,
		"password": fData.Password,
		"isAdmin":  fData.IsAdmin,
	}
	jsonValue, _ := json.Marshal(jsonData)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	if err != nil {
		fmt.Println("Error creating the request")
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}
	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}
	req.Header.Add("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		w.WriteHeader(500)
		e := alert{
			Type:    alertColor["ERR"],
			Message: "Internal error creating user.",
		}
		homeWithAlert(w, r, e)
		return
	}
	if response.StatusCode == 409 {
		w.WriteHeader(409)
		e := alert{
			Type:    alertColor["ERR"],
			Message: "Error creating user, username: " + fData.Username + " previously existed in system.",
		}
		homeWithAlert(w, r, e)
		return
	}
	a := alert{
		Type:    alertColor["OK"],
		Message: "User: " + fData.Username + " successfully created",
	}
	homeWithAlert(w, r, a)
}

func main() {
	router := newRouter()
	router.PathPrefix("/assets").Handler(http.StripPrefix("/assets", http.FileServer(http.Dir("views/assets/"))))
	fmt.Println("Listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
