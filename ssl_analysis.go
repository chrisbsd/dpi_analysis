package main

// A simple Golang program to help administrators with TLS/SSL related aspects.
// Especially useful for use with DPI SSL analysis from SonicWall.
// Author: chrisbsd

import (
	"net/http"
	"fmt"
	"crypto/tls"
	"os"
	"crypto/x509"
	"regexp"
	"strings"
)

func main() {
	
	// If you add a hash dont forget to add the description in the check_av function
	arr_hashes := []string {
		"df255af635a2dde04c031db95862f11e1bf44fe5cfc10d3b20bd4678ed818567",
		"33b62b95281bb0ecbad2523bb99e4853fd516044b8f2b42ef4a1e29903e7bd0f",
		"da0c0089713cfd5b47f425f23c23f9a9d82e62000873747dce1a73220319f93e",
		"94596876e5408289110c03aee0bf01dda5d9632d4614041e644bf4809fc46b5f",}
	if len(os.Args) != 2 {
		usage()
	} else if strings.HasPrefix(string(os.Args[1]), "https://") {
		test_ssl(os.Args[1])
	} else {
		switch os.Args[1] {
		case "options" : fmt.Println("Source: developer.mozilla.org\n\n" +
			"HSTS: \nEnforce the use of TLS/SSL in an user agent\n\n" +
			"Content Security Policy: \nThe HTTP Content-Security-Policy response header allows web site " +
				"administrators to control resources the user agent is allowed to load for a given page. " +
				"With a few exceptions, policies mostly involve specifying server origins and script endpoints. " +
				"This helps guard against cross-site scripting attacks (XSS).\n\n" +
			"X-Frame-Options: \nThe X-Frame-Options HTTP response header can be used to indicate whether or not a " +
				"browser should be allowed to render a page in a <frame>, <iframe> or <object> . Sites can use this " +
				"to avoid clickjacking attacks, by ensuring that their content is not embedded into other sites.\n\n" +
			"X-XSS-Protection: \nThe HTTP X-XSS-Protection response header is a feature of Internet Explorer, Chrome " +
				"and Safari that stops pages from loading when they detect reflected cross-site scripting (XSS) " +
				"attacks. Although these protections are largely unnecessary in modern browsers when sites " +
				"implement a strong Content-Security-Policy that disables the use of inline JavaScript " +
				"('unsafe-inline'), they can still provide protections for users of older web browsers that don't " +
				"yet support CSP.\n\n" +
			"X-Content-Type-Options: \nThe X-Content-Type-Options response HTTP header is a marker used by the server " +
				"to indicate that the MIME types advertised in the Content-Type headers should not be changed and be " +
				"followed. This allows to opt-out of MIME type sniffing, or, in other words, it is a way to say that " +
				"the webmasters knew what they were doing.\n\n" +
			"Referer-Policy: \nThe Referrer-Policy HTTP header governs which referrer information, sent in the Referer " +
				"header, should be included with requests made.")
		case "show_hashes": show_exhash(arr_hashes)
		case "check_av": check_av(arr_hashes, os.Args[2])
		default: usage()
		}
	}
}

func test_ssl(domain string){
	data, err := http.Get(domain)
	if err != nil {
		fmt.Println("There seems to be a problem with the certificate of", domain)
		fmt.Println(err)
		fmt.Println("Trying with skipped Security Verification...")
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		data2, err := client.Get(domain)
		if err != nil {
			fmt.Println(err)
		}else{
			fmt.Println("Skip Security Verification..")
			temp_header := data2.Header
			print_headers(temp_header)
			var_temp := domain[8:] + ":443"
			conf := &tls.Config{
				InsecureSkipVerify: true,
			}
			conn, err := tls.Dial("tcp", var_temp, conf)
			if err != nil {
				fmt.Println(err)
			}
			cert := conn.ConnectionState().PeerCertificates[0]

			defer conn.Close()
			print_values(cert)
		}
	} else {
		fmt.Println("Certificate seems okay... Lets check the HTTPS Response Header... \n ")
		temp_header := data.Header
		print_headers(temp_header)
		fmt.Println(" \nChecking the certificate...")
		var_temp := domain[8:] + ":443"
		conn, err := tls.Dial("tcp", var_temp, nil)
		if err != nil {
			fmt.Println(err)
		}
		cert := conn.ConnectionState().PeerCertificates[0]
		defer conn.Close()
		print_values(cert)
	}
}

func print_values(cert *x509.Certificate) {
	fmt.Println("\nThe Certificate was Issued by:\n", cert.Issuer,
		"\nHere are some additional Information about the Certificate:\n\nSubject:", cert.Subject,
		"\nStarts:", cert.NotBefore,
		"\nExpires:", cert.NotAfter,
		"\nDNS Names:", cert.DNSNames,
		"\nCrypto-Algorithm:  ", cert.SignatureAlgorithm,
		"\nIssues URL:  ", cert.IssuingCertificateURL)
}

func print_headers(temp_header http.Header) {
	arr_regex := [7]string{ "X-Xss-Protection", "X-Frame-Options", "Strict-Transport-Security",
		"Content-Security-Policy", "X-Content-Type-Options", "Public-Key-Pins", "Referrer-Policy" }
	fmt.Println("Your HTTPS Response was checked for these Security Options: ", arr_regex)
	x := 0
	y := 0
	srv_vers := "nil"
	for _, value := range arr_regex {
		for key, val := range temp_header {
			if key == "Server" {
				justString := strings.Join(val," ")
				srv_vers = justString
			}
			r, err := regexp.Compile(value)
			if err != nil {
				fmt.Printf("There is a problem with your regexp.\n")
				continue
			}
			if r.MatchString(key) == true {
				fmt.Println("The following Security Option was found: ", key)
				x += 1
				y = 1
			}
		}
	if y==0 {
		fmt.Println("NOT implemented ", value)
	}else {
		y = 0
	}
	}
	fmt.Println(x, " activated Security Options were found in your response!")
	if x == 0 {
		fmt.Println("You have no Security Options activated! You should do this immediately!")
	}
	fmt.Println("\n\nServer Version is:",srv_vers)
}
// "81.169.250.137:443"

func check_av(hashes []string, adr string) {
	conf := &tls.Config{
		// Uncomment this if your certificate has some problems
		//InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", adr, conf)
	if err != nil {
		fmt.Println(err)
	}
	defer conn.Close()
	for _, value := range hashes {
		conn.Write([]byte(value))
	}
}

func show_exhash(arr_h []string) {
	fmt.Println("Those are example SHA256 Hashes from REAL malware")
	add_hashes := []string {
		"OS:Win32 Type:exe Description: Locky variant 10/2017",
		"OS:Win32 Type:exe Description: File Replication Malware",
		"OS:Win32 Type:exe Description: Generic Trojan Malware",
		"OS:Win32 Type:exe Description: Trojan Dropper",
	}
	for i, value := range arr_h {
		fmt.Println(add_hashes[i], "\n", value)
	}
}
func usage(){
	fmt.Println("Usage: go run ssl_analysis.go https://<domain.tld>\n" +
		"If you want to get information about the security options in the header use: \n" +
		"   go run ssl_analysis.go options\nTest SonicWall AV with DPI-SSL with the example hashes: \n" +
		"   go run ssl_analysis check_av <address:port>\nShow all example Hashes:\n" +
		"   go run ssl_analysis show_hashes")
}