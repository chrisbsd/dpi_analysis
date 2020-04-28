package main

// A simple Golang program to help administrators with TLS/SSL related aspects.

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

)

type TLSAnalysis struct {

	domain string
	insecure bool
	Version string
	XXssProtection string
	XFrameOptions string
	HSTS string
	CSP string
	XContentTypeOptions string
	PublicKeyPins string
	ReferrerPolicy string
	FeaturePolicy string
	ExpectCT string
	certNames []string
	certFrom time.Time
	certTo time.Time
	certAlgo x509.SignatureAlgorithm
	certSig []byte
	certIssuer pkix.Name
	certIssuerURL []string
	server string

}

func main(){
	muh := TLSAnalysis{}
	tmpDomain := os.Args[1]
	if strings.HasPrefix("https://", tmpDomain) || strings.HasSuffix("/", tmpDomain) {
		printUsage()
		os.Exit(0)
	}
	muh.domain = tmpDomain
	muh.execute()
	muh.printHeader()
	fmt.Println()
	muh.printCert()
}

func printUsage() {
	fmt.Println("go run ssl_analysis.go google.com")
	fmt.Println("Or build it with go build")
}
func (t *TLSAnalysis) execute(){
	var tmpHeader http.Header
	var tmpConn *tls.Conn
	if t.insecure == false {
		client := &http.Client{}
		data, err := client.Get("https://"+t.domain)
		if err != nil {
			fmt.Println(err)
		}
		tmpHeader = data.Header
		conf := &tls.Config{
		}
		conn, err := tls.Dial("tcp", t.domain+":443", conf)
		if err != nil {
			fmt.Println(err)
		}
		tmpConn = conn
	} else {
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		data, err := client.Get("https://"+t.domain)
		if err != nil {
			fmt.Println(err)
		}
		tmpHeader = data.Header
		conn, err := tls.Dial("tcp", t.domain+":443", conf)
		if err != nil {
			fmt.Println(err)
		}
		tmpConn = conn
	}
	t.analyseHeader(tmpHeader)
	t.analyseCert(tmpConn)

}

func (t *TLSAnalysis) analyseCert(tmpConn *tls.Conn) {
	t.convertVersion(tmpConn.ConnectionState().Version)
	cert := tmpConn.ConnectionState().PeerCertificates[0]
	defer tmpConn.Close()
	t.certFrom = cert.NotBefore
	t.certTo = cert.NotAfter
	t.certNames = cert.DNSNames
	t.certIssuer = cert.Issuer
	t.certIssuerURL = cert.IssuingCertificateURL
	t.certSig = cert.Signature
	t.certAlgo = cert.SignatureAlgorithm
}

func (t *TLSAnalysis) convertVersion(version uint16) {

	hexVersion := fmt.Sprintf("%x", version)
	switch string(hexVersion) {
	case "300":
		t.Version = "SSLv3"
	case "301":
		t.Version = "TLS 1.0"
	case "302":
		t.Version = "TLS 1.1"
	case "303":
		t.Version = "TLS 1.2"
	case "304":
		t.Version = "TLS 1.3"
	}
}

func (t *TLSAnalysis) printCert(){
	fmt.Println("TLS Version: " + t.Version)
	fmt.Println("Certificate valid from: " + t.certFrom.String())
	fmt.Println("Certificate valid until: " + t.certTo.String())
	fmt.Printf("Certificate DNS Names: %v\n", t.certNames)
	fmt.Printf("Certificate Issuer: %v\n", t.certIssuer)
	fmt.Printf("Certificate Issuer URL: %v\n", t.certIssuerURL)
	fmt.Printf("Certificate Signature Algorithm: %v\n", t.certAlgo)
}

func (t *TLSAnalysis) analyseHeader(tmpHeader http.Header) {
	httpHeaders := [10]string{"X-Xss-Protection","X-Frame-Options" ,"strict-transport-security" ,
		"Content-Security-Policy","X-Content-Type-Options" ,"Public-Key-Pins" ,"Referrer-Policy" ,
		"Feature-Policy","Expect-CT" , "Server"}
	//fmt.Println(tmpHeader)
	for _, value := range httpHeaders {
		switch value {
		case "X-Xss-Protection":
			t.XXssProtection = tmpHeader.Get(value)
		case "X-Frame-Options":
			t.XFrameOptions = tmpHeader.Get(value)
		case "strict-transport-security":
			t.HSTS = tmpHeader.Get(value)
		case "Content-Security-Policy":
			t.CSP = tmpHeader.Get(value)
		case "X-Content-Type-Options":
			t.XContentTypeOptions = tmpHeader.Get(value)
		case "Public-Key-Pins":
			t.PublicKeyPins = tmpHeader.Get(value)
		case "Referrer-Policy":
			t.ReferrerPolicy = tmpHeader.Get(value)
		case "Feature-Policy":
			t.FeaturePolicy = tmpHeader.Get(value)
		case "Expect-CT":
			t.ExpectCT = tmpHeader.Get(value)
		case "Server":
			t.server = tmpHeader.Get(value)
		}
	}
}

func (t *TLSAnalysis) printHeader() {
	fmt.Println("Serverversion: " + t.server)
	fmt.Println("X-XSS-Protection: " + t.XXssProtection)
	fmt.Println("X-Frame-Options: " + t.XFrameOptions)
	fmt.Println("HSTS: "+ t.HSTS)
	fmt.Println("CSP: " + t.CSP)
	fmt.Println("X-Content-Type-Options: " + t.XContentTypeOptions)
	fmt.Println("Public-Key-Pins: " + t.PublicKeyPins)
	fmt.Println("Referrer-Policy: " + t.ReferrerPolicy)
	fmt.Println("Feature-Policy: " + t.FeaturePolicy)
	fmt.Println("Expect-CT: " + t.ExpectCT)
}

