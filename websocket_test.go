package rproxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/net/websocket"
)

func testWebsocketProxy(t *testing.T, newServer func(h http.Handler) *httptest.Server) {
	echoServer := http.NewServeMux()
	echoServer.Handle("/echo/ws", websocket.Handler(func(ws *websocket.Conn) {
		io.Copy(ws, ws)
	}))
	backend := newServer(echoServer)
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	proxyHandler.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	u, err := url.Parse(frontend.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Scheme = "ws"
	u.Path = "/echo/ws"
	ws, err := websocket.Dial(u.String(), "", frontend.URL)
	if err != nil {
		t.Fatal(err)
	}

	err = websocket.Message.Send(ws, "Hello Websocket")
	if err != nil {
		t.Fatal(err)
	}

	var s string
	err = websocket.Message.Receive(ws, &s)
	if err != nil {
		t.Fatal(err)
	}
	if s != "Hello Websocket" {
		t.Errorf("got %s, expected Hello Websocket", s)
	}
}

func TestWebSocketProxy(t *testing.T) {
	testWebsocketProxy(t, httptest.NewServer)
	testWebsocketProxy(t, httptest.NewTLSServer)
}
