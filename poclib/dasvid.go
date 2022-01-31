package dasvid

import (

	"bytes"
	"strings"
	"encoding/base64"
	"fmt"
	
	// To sig. validation 
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256"
	"encoding/binary"
	"math/big"

	// to retrieve JWT claims
	// NOTE: look for another JWT lib
	"time"
		
	// // to retrieve PrivateKey
	"bufio"
	"crypto/x509"
    "encoding/pem"

	// to jwt generation
	// "gopkg.in/square/go-jose.v2"
	// "gopkg.in/square/go-jose.v2/cryptosigner"
	// mintJWT "gopkg.in/square/go-jose.v2/jwt"
	mint "github.com/golang-jwt/jwt"
	JWTworker "github.com/dgrijalva/jwt-go"
	"flag"

	// To introspectAccessToken (online)
	"os"
	"io/ioutil"
	"net/http"
	"encoding/json"

	// To fetch SVID
	"context"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
)

// Worload API socket path
const socketPath = "unix:///tmp/spire-agent/public/api.sock"

type SVID struct {
	// ID is the SPIFFE ID of the X509-SVID.
	ID spiffeid.ID

	// Certificates are the X.509 certificates of the X509-SVID. The leaf
	// certificate is the X509-SVID certificate. Any remaining certificates (
	// if any) chain the X509-SVID certificate back to a X.509 root for the
	// trust domain.
	Certificates []*x509.Certificate

	// PrivateKey is the private key for the X509-SVID.
	PrivateKey crypto.Signer
}

type X509Context struct {
	// SVIDs is a list of workload X509-SVIDs.
	SVIDs []*x509svid.SVID

	// Bundles is a set of X.509 bundles.
	Bundles *x509bundle.Set
}

type JWKS struct {
	Keys []JWK
}

type JWK struct {
	Alg string
	Kty string
	X5c []string
	N   string
	E   string
	Kid string
	X5t string
}

func VerifySignature(jwtToken string, key JWK) error {
	parts := strings.Split(jwtToken, ".")
	message := []byte(strings.Join(parts[0:2], "."))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	n, _ := base64.RawURLEncoding.DecodeString(key.N)
	e, _ := base64.RawURLEncoding.DecodeString(key.E)
	z := new(big.Int)
	z.SetBytes(n)
	//decoding key.E returns a three byte slice, https://golang.org/pkg/encoding/binary/#Read and other conversions fail
	//since they are expecting to read as many bytes as the size of int being returned (4 bytes for uint32 for example)
	var buffer bytes.Buffer
	buffer.WriteByte(0)
	buffer.Write(e)
	exponent := binary.BigEndian.Uint32(buffer.Bytes())
	publicKey := &rsa.PublicKey{N: z, E: int(exponent)}

	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed.
	hasher := crypto.SHA256.New()
	hasher.Write(message)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hasher.Sum(nil), signature)
	return err
}

func Mintdasvid(iss string, sub string, dpa string, dpr string, key interface{}) string{

	 // gets current time and sets default for exp time
	 issue_time := time.Now().Round(0).Unix()
	 exp_time := time.Now().Add(time.Hour * 24).Round(0).Unix()
 
	 // TODO: enable entering values as flags or ordered arguments
	 // Declaring flags
	 issuer := flag.String("iss", iss, "issuer(iss) = SPIFFE ID of the workload that generated the DA-SVID (Asserting workload")
	 assert := flag.Int64("aat", issue_time, "asserted at(aat) = time at which the assertion made in the DA-SVID was verified by the asserting workload")
	 exp := flag.Int64("exp", exp_time, "expiration time(exp) = as small as reasonably possible, issue time + 1s by default.")
	 subj := flag.String("sub", sub, "subject (sub) = the identity about which the assertion is being made. Subject workload's SPIFFE ID.")
	 dlpa := flag.String("dpa", dpa, "delegated authority (dpa) = ")
	 dlpr := flag.String("dpr", dpr, "delegated principal (dpr) = The Principal")
 
	 flag.Parse()
 
	 // Building JWT
	 token := mint.NewWithClaims(mint.SigningMethodES256, mint.MapClaims{
		//  "typ": "JWT",
		//  "alg": "HS256",
		"exp": *exp,
		//  "dasvid": map[string]interface{}{
			"iss": *issuer,
			"aat": *assert,
			"sub": *subj,
			"dpa": *dlpa,
			"dpr": *dlpr,
			"iat": issue_time,
		//  },
	 })
 
 	 tokenString, err := token.SignedString(key)
 
	 //JWT gen error handling
	 if err != nil {
 
		 fmt.Println(err)
 
	 }
 
		//  fmt.Println(tokenString)
		return tokenString
 
}

func ParseTokenClaims(strAT string) map[string]interface{} {
		// Parse access token without validating signature
		token, _, err := new(JWTworker.Parser).ParseUnverified(strAT, JWTworker.MapClaims{})
		if err != nil {
			fmt.Println(err)
		}
		claims, _ := token.Claims.(JWTworker.MapClaims)
		
		return claims
}

func ValidateTokenExp(claims map[string]interface{}) (expresult string) {

	// 	// Verify if token is still valid
	tm := time.Unix(int64(claims["exp"].(float64)), 0)
	remaining := tm.Sub(time.Now())
	// fmt.Println("remaining value")
	// fmt.Println(remaining)
	if remaining > 0 {
		expresult = fmt.Sprintf("Token valid for more %v", remaining) 
		// fmt.Println("Token valid for more %v", remaining) 
	} else {
		expresult = fmt.Sprintf("Token expired!")
		// fmt.Println("Token expired!")
	}

	return expresult

}

func InstrospectAccessToken(t string) map[string]interface{}  {

	payload := strings.NewReader(`token=`+t)

	m := make(map[string]interface{})
	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(os.Getenv("CLIENT_ID") + ":" + os.Getenv("CLIENT_SECRET")))

	reqUrl := os.Getenv("ISSUER") + "/v1/introspect"

	req, _ := http.NewRequest("POST", reqUrl, payload)
	h := req.Header
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Authorization", "Basic "+authHeader)
	h.Add("Accept", "application/json")

	// h.Add("token", t)
	// h.Add("token_type_hint", "access_token")
	
	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	json.Unmarshal(body, &m)

	return m
}

func RetrievePrivateKey(path string) interface{} {
	// Open file containing private Key
	privateKeyFile, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	pemdata, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()

	// Extract Private Key
	privateKeyImported, err := x509.ParsePKCS8PrivateKey(pemdata.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return privateKeyImported
}

func RetrievePublicKey(path string) interface{} {

	// Open file containing private Key
	privateKeyFile, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	pemdata, _ := pem.Decode([]byte(pembytes))
	cert, _ := x509.ParseCertificate(pemdata.Bytes)
	privateKeyFile.Close()

	// // Extract Private Key
	// privateKeyImported, err := x509.ParsePKCS8PrivateKey(pemdata.Bytes)
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }

	publicKey, _ := x509.MarshalPKIXPublicKey(&cert.PublicKey)

	// strpubkey := fmt.Sprintf("%v", publicKey)
	// fmt.Println(strpubkey)

	return publicKey
}

func RetrieveJWKSPublicKey(path string) JWKS {
	    // Open file containing the keys obtained from /keys endpoint
	// NOTE: Needs to implement cache and retrieve processes
	jwksFile, err := os.Open(path)
	if err != nil {
		fmt.Println("Error in reading jwks")
		os.Exit(1)
	}

	// Decode file and retrieve Public key from Okta application
	dec := json.NewDecoder(jwksFile)
	var jwks JWKS
	
	if err := dec.Decode(&jwks); err != nil {
		fmt.Println("Unable to read key %s", err)
		os.Exit(1)
	}

	return jwks
}

func ExampleFetchJWTSVID() {	


	serverID, err := spiffeid.Join("example.org", "server")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	svid, err := workloadapi.FetchJWTSVID(context.TODO(), jwtsvid.Params{
		Audience: serverID,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// TODO: use the JWT-SVID
	svid = svid
}

func FetchX509SVID() *x509svid.SVID {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	// If socket path is not defined using `workloadapi.SourceOption`, value from environment variable `SPIFFE_ENDPOINT_SOCKET` is used.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		fmt.Println("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return svid
}