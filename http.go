package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/googollee/go-socket.io"
	"strings"
	"strconv"
	"log"
	"net/http"
	"regexp"
	"text/template"
)

func generateToken() string {
	var token [14]byte
	rand.Read(token[:])
	return hex.EncodeToString(token[:])
}

var socketioLocation = "/socket.io"
var socketioPathRe = regexp.MustCompile(`^` + regexp.QuoteMeta(socketioLocation) + `(/|$)`)
var historyPathRe = regexp.MustCompile(`^/([a-fA-F0-9]{28})/history$`)
var tokenPathRe = regexp.MustCompile(`^/([a-fA-F0-9]{28})(/|)$`)
var pathPingRe = regexp.MustCompile(`^/p(|/)([a-fA-F0-9]{28})(/|$)`)
var acmeLocation = "/.well-known/acme-challenge/"
var acmeRe = regexp.MustCompile(`^` + regexp.QuoteMeta(acmeLocation) + `([a-zA-Z0-9_-]+)$`)
var levar = "/var/lib/letsencrypt"


func handleHttpPing(w http.ResponseWriter, r *http.Request, path string, token string, ret chan<- Record) {
    ip := r.RemoteAddr
    if v, ok := r.Header["X-Forwarded-For"]; ok && len(v) > 0 {
        ip = v[0]
    }
    host := r.Host
    if v, ok := r.Header["X-Real-Host"]; ok && len(v) > 0 {
        host = v[0]
    }
    header := NewRecordHeader(ip, token, "http", nil)
    ret <- &HttpRecord{
        RecordHeader: header,
        Domain:		  host,
        Path:		  path,
        Headers:	  r.Header,
    }
}

func handleUI(w http.ResponseWriter, r *http.Request, token string, appHtml *template.Template, httpHost string, httpHostPort string) {
    err := appHtml.Execute(w, &struct {
        HttpHost		string
        HttpHostPort	string
        Token	string
        History []Record
    }{httpHost, httpHostPort, token, History(token)})
    if err != nil {
        log.Println(err)
    }
}

func handleHistory(w http.ResponseWriter, r *http.Request, token string) {
    history := History(token)
    if history == nil {
        history = []Record{}
    }
    j, err := json.Marshal(history)
    if err != nil {
        log.Println(err)
    } else {
        w.Write(j)
    }
}

func handleWalkIn(w http.ResponseWriter, r *http.Request) {
    token := generateToken()
    http.Redirect(w, r, "/" + token, 302)
}

func handleAcme(w http.ResponseWriter, r *http.Request, path string) {
    // The following reads from /var/lib/letsencrypt/.well-known/acme-challenge/NNN,
    // assuming that certbot runs as follows and levar has the same value as webroot-path.
    //  certbot --webroot --webroot-path /var/lib/letsencrypt
    fpath := levar + path
    http.ServeFile(w, r, fpath)
}

type httpResponder struct {
    sockio *socketio.Server
    ret chan<- Record
    appHtml *template.Template
    httpHost string
    httpHostPort string
}

// At the time of the incoming HTTP request, choose how to process it.
// Thanks icza https://stackoverflow.com/questions/30474313/how-to-use-regexp-get-url-pattern-in-golang
func (responder *httpResponder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
    path := r.URL.Path

    matches := pathPingRe.FindStringSubmatch(path)
    if len(matches) == 4 {
        // When beaconing with a web request such as with SSRF or RCE curl: "GET /p/HEX28"
        // When beaconing with access to a share name \\SERVER\pHEX28\FILE.EXT via Microsoft WebDAV: "ANYTHING /pHEX28"
        handleHttpPing(w, r, path, matches[2], responder.ret)
        return
    }

    matches = tokenPathRe.FindStringSubmatch(path)
    if len(matches) == 3 {
        if (r.Method == "PROPFIND") || (r.Method == "OPTIONS") {
            // When beaconing with access to a share name \\SERVER\HEX28\FILE.EXE via Microsoft WebDAV:
            // "PROPFIND /HEX28/" and "OPTIONS /HEX28/"
            handleHttpPing(w, r, path, matches[1], responder.ret)
        } else {
            // When getting redirected from a "walk-in"
            handleUI(w, r, matches[1], responder.appHtml, responder.httpHost, responder.httpHostPort)
        }
        return
    }

    matches = historyPathRe.FindStringSubmatch(path)
    if len(matches) == 2 {
        handleHistory(w, r, matches[1])
        return
    }

    if socketioPathRe.MatchString(path) {
        responder.sockio.ServeHTTP(w, r)
        return
    }

    matches = acmeRe.FindStringSubmatch(path)
    if len(matches) == 2 {
        handleAcme(w, r, path)
        return
    }

    if path == "/favicon.ico" {
        http.Error(w, "Not found", 404)
        return
    }

    handleWalkIn(w, r)
}

func Http(listen string, httpHost string) (<-chan Record, error) {
	sockio := socketio.NewServer(nil)
	sockio.OnEvent("/", "subscribe", func(s socketio.Conn, topic string) {
		events := Subscribe(topic)
		sockio.OnDisconnect("/", func(s socketio.Conn, msg string) {
			Unsubscribe(topic, events)
		})
		go func() {
			for e := range events {
				v, err := json.Marshal(e)
				if err != nil {
					log.Println(err)
				} else {
					s.Emit(topic, string(v))
				}
			}
		}()
	})
	appHtml, err := template.ParseFiles("templates/app.html")
	if err != nil {
		log.Fatal(err)
	}

	addrPortList := strings.Split(listen, ":")
	var addr string
	var port int
	if len(addrPortList) == 1 {
		addr = listen
		port = 80
	} else if len(addrPortList) == 2 {
		addr = addrPortList[0]
		port, err = strconv.Atoi(addrPortList[1])
		if err != nil {
			panic(err)
		}
	} else {
		panic("The listen address \"" + listen + "\" needs to be HOST:PORT")
	}
	listenAddrPort := addr + ":" + strconv.Itoa(port)
	var httpHostPort string
	if port == 80 {
		httpHostPort = httpHost
	} else {
		httpHostPort = httpHost + ":" + strconv.Itoa(port)
	}

    // Create a channel that receives HTTP pings.  Return it at the end of this
    // setup to allow publishing the ping events to subscribers.
    ret := make(chan Record)
    // Set up a single handler for all incoming HTTP requests.
    http.Handle("/", &httpResponder{sockio, ret, appHtml, httpHost, httpHostPort})

	go func() {
		go sockio.Serve()
		defer sockio.Close()
		err := http.ListenAndServe(listenAddrPort, nil)
		if err != nil {
			log.Fatal(err)
		}
	}()
	return ret, nil
}
