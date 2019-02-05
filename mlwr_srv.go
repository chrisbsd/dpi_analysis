package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
)

func start_server(pw string, to string, from string, host string, port string, cert string, key string) {
	fmt.Println("Starting Server... Listening for Malware Hashes")
	cer, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		fmt.Println(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		go handle_conn(conn, pw, to, from, host, port)
	}
}
func handle_conn(conn net.Conn, pw string, to string, from string, host string, port string) {
	message, _ := bufio.NewReader(conn).ReadString('\n')
	send_mail(pw, message, to, from, host, port)
}

func main() {
	start_server(os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6], os.Args[7])
}

func send_mail(pw string, hash string, to string, from string, host string, port string) {
	auth := smtp.PlainAuth(
		"",
		from,
		pw,
		host,
	)
	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: Malware Transmission\n\n" +
		"The following hash was transmitted without discovery from SonicWall AV: \n" + hash
	address := host + ":" + port
	err := smtp.SendMail(
		address,
		auth,
		from,
		[]string{to},
		[]byte(msg),
	)
	if err != nil {
		fmt.Println(err)
	}
}
