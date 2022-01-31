package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"net"
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	
	// dasvid lib test
	dasvid "github.com/marco-developer/dasvid/poclib"

	// To sig. validation 
	_ "crypto/sha256"
	
	"github.com/gorilla/sessions"
	// Okta
	verifier "github.com/okta/okta-jwt-verifier-golang"
	oktaUtils "github.com/okta/samples-golang/okta-hosted-login/utils"
)

var (
	tpl          *template.Template
	sessionStore = sessions.NewCookieStore([]byte("okta-hosted-login-session-store"))
	state        = generateState()
	nonce        = "NonceNotSetYet"
)

const (
	// Workload API socket path
	socketPath    = "unix:///tmp/spire-agent/public/api.sock"
)

type PocData struct {
	Profile         map[string]string
	IsAuthenticated bool
	HaveDASVID		bool
	// Added filds in the customData
	AccessToken     string
	PublicKey		string
	SigValidation 	string
	ExpValidation 	string
	RetClaims		map[string]interface{}
	DASVIDToken		string
	DASVIDClaims 	map[string]interface{}
	DasvidExpValidation string
	Returnmsg		string
		
}

type Contents struct {
	OauthSigValidation 			*bool `json:",omitempty"`
	OauthExpValidation 			*bool `json:",omitempty"`
	OauthExpRemainingTime		string `json:",omitempty"`
	DASVIDToken					string `json:",omitempty"`
}

var temp Contents
var oktaclaims map[string]interface{}
var dasvidclaims map[string]interface{}

var Data PocData

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func generateState() string {
	// Generate a random byte array for state paramter
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func GetOutboundIP() net.IP {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)

    return localAddr.IP
}

func main() {
	oktaUtils.ParseEnvironment()

	// Retrieve local IP
	Iplocal := GetOutboundIP()
	StrIPlocal := fmt.Sprintf("%v", Iplocal)
	uri := StrIPlocal + ":8080"
	

	//  APIs:
	//  1- Subj WL
	//  2- Asserting WL (mint, validate)

	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/callback", AuthCodeCallbackHandler)
	http.HandleFunc("/profile", ProfileHandler)
	http.HandleFunc("/logout", LogoutHandler)
	// http.HandleFunc("/step1", step1_validateoauth)
	// http.HandleFunc("/step2a", step2a_decodeoauth)
	http.HandleFunc("/checkfunds", CheckfundsHandler)
	http.HandleFunc("/getdasvid", GetdasvidHandler)
	// http.HandleFunc("/step3", step3_validatedasvid)
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("./img"))))

	log.Print("Subject workload starting at ", uri)
	err := http.ListenAndServe(uri, nil)
	if err != nil {
		log.Printf("the Subject workload HTTP server failed to start: %s", err)
		os.Exit(1)
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// Convert access token retrieved from session to string
	strAT := fmt.Sprintf("%v", session.Values["access_token"])
	
	Data = PocData{
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
		HaveDASVID:		 haveDASVID(),
		// Pass access token as part of Data
		AccessToken:	 strAT,
	}

	
	tpl.ExecuteTemplate(w, "home.gohtml", Data)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20
	
	// Retrieve local IP
	Iplocal := GetOutboundIP()
	StrIPlocal := fmt.Sprintf("%v", Iplocal)
	uri := "http://" + StrIPlocal + ":8080/callback"
	
	nonce, _ = oktaUtils.GenerateNonce()
	var redirectPath string

	q := r.URL.Query()
	q.Add("client_id", os.Getenv("CLIENT_ID"))
	q.Add("response_type", "code") // code or token
	q.Add("response_mode", "query") // query or fragment
	q.Add("scope", "openid profile email")
	q.Add("redirect_uri", uri)
	q.Add("state", state)
	q.Add("nonce", nonce)

	redirectPath = os.Getenv("ISSUER") + "/v1/authorize?" + q.Encode()

	http.Redirect(w, r, redirectPath, http.StatusFound)
}

func AuthCodeCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Check the state that was returned in the query string is the same as the above state
	if r.URL.Query().Get("state") != state {
		fmt.Fprintln(w, "The state was not as expected")
		return
	}
	// Make sure the code was provided
	if r.URL.Query().Get("code") == "" {
		fmt.Fprintln(w, "The code was not returned or is not accessible")
		return
	}

	exchange := exchangeCode(r.URL.Query().Get("code"), r)
	if exchange.Error != "" {
		fmt.Println(exchange.Error)
		fmt.Println(exchange.ErrorDescription)
		return
	}

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	_, verificationError := verifyToken(exchange.IdToken)

	if verificationError != nil {
		log.Fatal(verificationError)
	}

	os.Setenv("oauthtoken", exchange.AccessToken)

	// Remove session soon... useless 
	session.Values["id_token"] = exchange.IdToken
	session.Values["access_token"] = exchange.AccessToken
	session.Save(r, w)
	

	http.Redirect(w, r, "/", http.StatusFound)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {

	Data = PocData{
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
		HaveDASVID:		 haveDASVID(),
	}
	tpl.ExecuteTemplate(w, "profile.gohtml", Data)
}

func step1_validateoauth(w http.ResponseWriter, r *http.Request) {
	
	var sigresult string
	var expresult string

	// Retrieve claims and validate token exp without signature
	oktaclaims = dasvid.ParseTokenClaims(Data.AccessToken)
	expresult = dasvid.ValidateTokenExp(oktaclaims)

	// Retrieve Public Key from JWKS file
	pubkey := dasvid.RetrieveJWKSPublicKey("./jwks.json")

	// Verify token signature using extracted Public key
	err := dasvid.VerifySignature(Data.AccessToken, pubkey.Keys[0])
	if err != nil {
		sigresult = fmt.Sprintf("Failed signature verification: %v", err)
	} else {
		sigresult = "Signature successfuly validated!"
	}

	Data = PocData{
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
		// Token validation info
		SigValidation:	 sigresult,
		ExpValidation: 	 expresult,
		PublicKey: 		 fmt.Sprintf("%v", pubkey.Keys[0]),
		RetClaims:		 oktaclaims, 
	}

	tpl.ExecuteTemplate(w, "validate.gohtml", Data)

}

func step3_validatedasvid(w http.ResponseWriter, r *http.Request) {
	
	var dasvidexpresult string
	
	// Retrieve claims and validate token exp without signature
	datoken := os.Getenv("dasvidtoken")
	strdatoken := fmt.Sprintf("%v", datoken)

	dasvidclaims = dasvid.ParseTokenClaims(strdatoken)
	dasvidexpresult = dasvid.ValidateTokenExp(dasvidclaims)

	// 	// Retrieve Public Key from JWKS file
	// 	// pubkey := dasvid.RetrieveJWKSPublicKey("./dasvidkey.json")
	// 	pubkey := dasvid.RetrievePublicKey("./svid.0.pem")

	// 	// Verify token signature using extracted Public key
	// 	// err := dasvid.VerifySignature(Data.DASVIDToken, pubkey)
	// 	// if err != nil {
	// 	// 	dasvidsigresult = fmt.Sprintf("Failed signature verification: %v", err)
	// 	// } else {
	// 	// 	dasvidsigresult = "Signature successfuly validated!"
	// 	// }
	
	Data = PocData{
		Profile:         		getProfileData(r),
		IsAuthenticated: 		isAuthenticated(r),
		DasvidExpValidation: 	dasvidexpresult,
		DASVIDClaims:			dasvidclaims,
	}
	
	tpl.ExecuteTemplate(w, "decodedasvid.gohtml", Data)

}

func step2a_decodeoauth(w http.ResponseWriter, r *http.Request) {
	
	Data = PocData{
		Profile:         	 getProfileData(r),
		IsAuthenticated: 	 isAuthenticated(r),
		RetClaims:		 	 oktaclaims,
	}
	
	tpl.ExecuteTemplate(w, "decode.gohtml", Data)

}

func GetdasvidHandler(w http.ResponseWriter, r *http.Request) {

	receivedresponse := getdasvid(os.Getenv("oauthtoken"))

	json.Unmarshal([]byte(receivedresponse), &temp)
	// if err != nil {
	// 	log.Fatalf("error:", err)
	// }

	if (*temp.OauthSigValidation != true) || (*temp.OauthExpValidation == false) {

		returnmsg := "Oauth token validation error"

		Data = PocData{
			Returnmsg: returnmsg,
		}

		log.Printf(returnmsg)
		tpl.ExecuteTemplate(w, "dasvidgenerated.gohtml", Data)
	}

	os.Setenv("DASVIDToken", temp.DASVIDToken)
	// fmt.Println(os.Getenv("DASVIDToken"))

	Data = PocData{
		Profile:         		getProfileData(r),
		IsAuthenticated: 		isAuthenticated(r),
		DASVIDToken:			temp.DASVIDToken,
		HaveDASVID:				haveDASVID(),
		SigValidation: 			fmt.Sprintf("%v", temp.OauthSigValidation),
		ExpValidation:			fmt.Sprintf("%v", temp.OauthExpValidation),
	}

	tpl.ExecuteTemplate(w, "dasvidgenerated.gohtml", Data)


}

func CheckfundsHandler(w http.ResponseWriter, r *http.Request) {

	
	// With dasvid, app can make a call to middle tier, asking for user funds.

	// Result
	
	// Logo	< M    E   N  U   > 

	// Client: 			Client_name
	// Consulting App: 	Subject_name
	// Token Issuer:	issuer_name
	// Issued at time:	iat
	// ZKP:				zkp
	
	// Request Date/time
	// Requested Data (funds)



}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	delete(session.Values, "id_token")
	delete(session.Values, "access_token")

	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func exchangeCode(code string, r *http.Request) Exchange {

	// Retrieve local IP
	Iplocal := GetOutboundIP()
	StrIPlocal := fmt.Sprintf("%v", Iplocal)
	uri := "http://" + StrIPlocal + ":8080/callback"

	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(os.Getenv("CLIENT_ID") + ":" + os.Getenv("CLIENT_SECRET")))

	q := r.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Set("code", code)
	q.Add("redirect_uri", uri)

	url := os.Getenv("ISSUER") + "/v1/token?" + q.Encode()

	req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Basic "+authHeader)
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	var exchange Exchange
	json.Unmarshal(body, &exchange)

	return exchange
}

func isAuthenticated(r *http.Request) bool {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}

	return true
}

func haveDASVID() bool {

	if os.Getenv("DASVIDToken") == "" {
		return false
	}

	return true
}

func getProfileData(r *http.Request) map[string]string {
	m := make(map[string]string)

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m
	}

	reqUrl := os.Getenv("ISSUER") + "/v1/userinfo"

	req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	json.Unmarshal(body, &m)

	return m
}

func verifyToken(t string) (*verifier.Jwt, error) {
	tv := map[string]string{}
	tv["nonce"] = nonce
	tv["aud"] = os.Getenv("CLIENT_ID")
	jv := verifier.JwtVerifier{
		Issuer:           os.Getenv("ISSUER"),
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(t)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	if result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("token could not be verified: %s", "")
}

type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}

func getdasvid(oauthtoken string) (string) {
	
	// Asserting workload will validate oauth token, so we dont need to do it here.
	// stablish mtls with asserting workload and call mint endpoint, passing oauth token 
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Retrieve local IP
	// In this PoC example, client and server are running in the same host, so serverIP = clientIP 
	Iplocal := GetOutboundIP()
	StrIPlocal := fmt.Sprintf("%v", Iplocal)
	serverURL := StrIPlocal + ":8443" // asserting workload is responding here

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Fatalf("Unable to create X509Source %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID
	serverID := spiffeid.RequireTrustDomainFromString("example.org")

	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match allowed SPIFFE ID rule
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(serverID))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	var endpoint string
	token := os.Getenv("oauthtoken")
	endpoint = "https://"+serverURL+"/mint?AccessToken="+token

	r, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", serverURL, err)
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	return fmt.Sprintf("%s", body)
}