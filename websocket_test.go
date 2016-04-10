package rproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/net/websocket"
)

func TestWebSocketProxy(t *testing.T) {
	echoServer := http.NewServeMux()
	echoServer.Handle("/echo/ws", websocket.Handler(func(ws *websocket.Conn) {
		io.Copy(ws, ws)
	}))
	backend := httptest.NewServer(echoServer)
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
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
