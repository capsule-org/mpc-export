package network

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

const (
	KEYGEN  ProtocolMethod = "KEYGEN"
	REFRESH ProtocolMethod = "REFRESH"
	PRESIGN ProtocolMethod = "PRESIGN"
	SIGN    ProtocolMethod = "SIGN"

	messagePollingMilliseconds = 300
	messageTimeoutMinutes      = 5
)

var networkClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	},
}

type ProtocolMethod string

// Network simulates a point-to-point network between different parties using Go channels.
// The same network is used by all processes, and can be reused for different protocols.
// When used with test.Handler, no interaction from the user is required beyond creating the network.
type Network struct {
	parties          []string
	listenChannels   map[string]chan map[string]interface{}
	done             chan struct{}
	closedListenChan chan map[string]interface{}
	mtx              sync.Mutex
	Host             string
	headers          map[string]string
}

type MessageRes struct {
	Messages []map[string]interface{} `json:"messages"`
}

func SetNetworkClientTransport(transport *http.Transport) {
	networkClient.Transport = transport
}

func GetRequest(url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return networkClient.Do(req)
}

func PostRequest(url string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return networkClient.Do(req)
}

func NewNetwork(parties []string, host string, headers map[string]string) *Network {
	closed := make(chan map[string]interface{})
	close(closed)
	c := &Network{
		parties:          parties,
		listenChannels:   make(map[string]chan map[string]interface{}, 2*len(parties)),
		closedListenChan: closed,
		Host:             host,
		headers:          headers,
	}

	return c
}

func CreateWallet(networkHost, walletId string, parties []string, headers map[string]string) {
	reqBody, _ := json.Marshal(map[string]interface{}{
		"participantIds": parties,
		"walletId":       walletId,
	})
	resp, err := PostRequest(fmt.Sprintf("%s/wallets", networkHost), bytes.NewBuffer(reqBody), headers)
	if err != nil {
		log.Panicln(err)
	}
	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Panicln(err)
	}
	var respBody map[string]interface{}
	err = json.Unmarshal(respBodyBytes, &respBody)
	if err != nil {
		log.Panicln(err)
	}
}

func CreateProtocol(networkHost, walletId string, protocol string, headers map[string]string) string {
	reqBody, _ := json.Marshal(map[string]interface{}{
		"method": protocol,
	})
	resp, err := PostRequest(fmt.Sprintf("%s/wallets/%s/protocols", networkHost, walletId), bytes.NewBuffer(reqBody), headers)
	if err != nil {
		log.Panicln(err)
	}
	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Panicln(err)
	}
	var respBody map[string]interface{}
	err = json.Unmarshal(respBodyBytes, &respBody)
	if err != nil {
		log.Panicln(err)
	}

	return respBody["protocolId"].(string)
}

func (n *Network) init(id string) {
	N := len(n.parties)
	n.listenChannels[id] = make(chan map[string]interface{}, N*N)
	n.done = make(chan struct{})
}

func (n *Network) Next(id, protocolId string, nextChan, doneChan chan struct{}, conn *websocket.Conn, wsDoneReadChan chan struct{}) (<-chan map[string]interface{}, error) {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	if len(n.listenChannels) == 0 {
		n.init(id)
	}
	c, ok := n.listenChannels[id]
	if !ok {
		return n.closedListenChan, nil
	}

	if conn != nil {
		if len(nextChan) == 0 {
			nextChan <- struct{}{}
			err := wsjson.Write(context.Background(), conn, map[string]interface{}{
				"action": "GET_MESSAGE",
			})
			if err != nil {
				return nil, err
			}

			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("Recovered from panic in func for ws read: %v\n", r)
						debug.PrintStack()
					}
				}()

				var readJson map[string]interface{}
				select {
				case <-wsDoneReadChan:
				default:
					return
				}
				err := wsjson.Read(context.Background(), conn, &readJson)
				wsDoneReadChan <- struct{}{}
				if err != nil {
					// server responded to our close message acknowledging it
					if websocket.CloseStatus(err) == websocket.StatusNormalClosure && len(doneChan) == 1 {
						return
					}
					log.Panicln(err)
					return
				}

				resultBytes, err := json.Marshal(readJson["result"])
				if err != nil {
					log.Panicln(err)
					return
				}

				// Unmarshal the JSON into our struct
				var result MessageRes
				err = json.Unmarshal(resultBytes, &result)
				if err != nil {
					log.Panicln(err)
					return
				}

				messages := result.Messages
				for i := range messages {
					msgPayload := messages[i]["payload"].(map[string]interface{})
					c <- msgPayload
				}
				<-nextChan
			}()
		}
		return c, nil
	}

	ticker := time.NewTicker(time.Millisecond * messagePollingMilliseconds)
	timeout := time.NewTimer(time.Minute * messageTimeoutMinutes)
	tickerChannel := ticker.C
	timeoutChannel := timeout.C

	if len(nextChan) == 0 {
		nextChan <- struct{}{}
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Recovered from panic in Next: %v\n", r)
					debug.PrintStack()
				}
			}()
			defer ticker.Stop()
			defer timeout.Stop()

			for {
				select {
				case <-doneChan:
					return
				case <-timeoutChannel:
					log.Println("timeout of", messageTimeoutMinutes, "minutes reached  for protocolId: ", protocolId)
					return
				case <-tickerChannel:
					// functionality to actually use a separate network
					resp, err := GetRequest(fmt.Sprintf("%s/protocols/%s/messages?isFor=%s&all=true", n.Host, protocolId, id), n.headers)
					if err != nil {
						log.Panicln(err)
					}
					respBodyBytes, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						log.Panicln(err)
					}
					defer resp.Body.Close()

					var respBody MessageRes
					err = json.Unmarshal(respBodyBytes, &respBody)
					if err != nil {
						log.Panicln(err)
					}

					if len(respBody.Messages) != 0 {
						ch, ok := n.listenChannels[id]
						if !ok {
							return
						}

						messages := respBody.Messages
						for i := range messages {
							msgPayload := messages[i]["payload"].(map[string]interface{})
							ch <- msgPayload
						}
						// got message and sent to be consumed through channel
						// can stop polling
						<-nextChan
						return
					}
				}
			}
		}()
	}

	return c, nil
}

func isFor(id string, msg map[string]interface{}) bool {
	if msg["From"] == id {
		return false
	}
	return msg["To"] == id
}

func isForAll(msg map[string]interface{}) bool {
	return msg["To"] == ""
}

func (n *Network) sendMessage(protocolId string, msg map[string]interface{}, conn *websocket.Conn) error {
	// n.listenChannels[id] <- msg
	// functionality to actually use a separate network
	reqBody, err := json.Marshal(map[string]interface{}{
		// just hardcoding for now but should actually pass in later
		// atm the network doesn't care what this is so shouldn't matter anyways
		"payload": msg,
		"isFrom":  msg["From"],
		"isFor":   msg["To"],
	})
	if err != nil {
		return err
	}

	if conn != nil {
		err = wsjson.Write(context.Background(), conn, map[string]interface{}{
			"action": "POST_MESSAGE",
			"body": map[string]interface{}{
				// just hardcoding for now but should actually pass in later
				// atm the network doesn't care what this is so shouldn't matter anyways
				"payload": msg,
				"isFrom":  msg["From"],
				"isFor":   msg["To"],
			},
		})
		if err != nil {
			return err
		}
		return nil
	}

	resp, err := PostRequest(fmt.Sprintf("%s/protocols/%s/messages", n.Host, protocolId), bytes.NewBuffer(reqBody), n.headers)
	if err != nil {
		return err
	}
	// just reading response for purpose of keep-alive to take effect
	io.Copy(ioutil.Discard, resp.Body)
	defer resp.Body.Close()
	return nil
}

func (n *Network) Send(protocolId string, msg map[string]interface{}, conn *websocket.Conn, pendingWriteChan chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in Send: %v\n", r)
			debug.PrintStack()
		}
		pendingWriteChan <- struct{}{}
	}()
	n.mtx.Lock()
	defer n.mtx.Unlock()

	if isForAll(msg) {
		err := n.sendMessage(protocolId, msg, conn)
		if err != nil {
			log.Panicln(err)
		}
		return
	}
	for _, id := range n.parties {
		if isFor(id, msg) {
			err := n.sendMessage(protocolId, msg, conn)
			if err != nil {
				log.Panicln(err)
			}
		}
	}
}

// hit POST protocols/:protocolId/messages with message
// this API should handle getting it to everyone needed

func (n *Network) Done(id string) chan struct{} {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	if _, ok := n.listenChannels[id]; ok {
		close(n.listenChannels[id])
		delete(n.listenChannels, id)
	}
	if len(n.listenChannels) == 0 {
		close(n.done)
	}
	return n.done
}

func remove(partyIDs []string, id string) []string {
	newPartyIDs := make([]string, 0, len(partyIDs))
	for _, partyID := range partyIDs {
		if partyID != id {
			newPartyIDs = append(newPartyIDs, partyID)
		}
	}
	return newPartyIDs
}

func (n *Network) Quit(id string) {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	n.parties = remove(n.parties, id)
}
