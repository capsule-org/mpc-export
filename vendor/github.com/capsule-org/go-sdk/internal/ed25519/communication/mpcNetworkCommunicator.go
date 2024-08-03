package communication

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/capsule-org/go-sdk/definitions"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

const (
	messagePollingMilliseconds = 300
	messageTimeoutSeconds      = 15
)

type messageRes struct {
	Messages []map[string]interface{} `json:"messages"`
}

type CapsuleCommunicator struct {
	id                          party.ID
	otherId                     party.ID
	host                        string
	protocolId                  string
	conn                        *websocket.Conn
	done                        chan struct{}
	incoming                    chan *messages.Message
	outgoing                    chan *messages.Message
	waitForIncomingMessages     bool
	waitForIncomingMessagesChan chan struct{}
	getMessagesDoneChan         chan struct{}
	sendMessagesDoneChan        chan struct{}
}

func NewCapsuleCommunicator(host, protocolId string, id, otherId party.ID, waitForIncomingMessages bool) *CapsuleCommunicator {
	c := &CapsuleCommunicator{
		id:                      id,
		otherId:                 otherId,
		host:                    host,
		protocolId:              protocolId,
		done:                    make(chan struct{}, 2),
		incoming:                make(chan *messages.Message, 3),
		outgoing:                make(chan *messages.Message, 3),
		waitForIncomingMessages: waitForIncomingMessages,
		getMessagesDoneChan:     make(chan struct{}, 1),
		sendMessagesDoneChan:    make(chan struct{}, 1),
	}
	if c.waitForIncomingMessages {
		c.waitForIncomingMessagesChan = make(chan struct{})
	}
	return c
}

var networkClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     15 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	},
}

func GetRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return networkClient.Do(req)
}

func PostRequest(url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return networkClient.Do(req)
}

func (c *CapsuleCommunicator) GetMessages(doneChan chan struct{}, useWebSockets bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in func for GetMessages: %v\n", r)
			debug.PrintStack()
		}
		doneChan <- struct{}{}
	}()

	for {
		select {
		case <-c.done:
			return
		default:
		}

		var result messageRes
		if useWebSockets {
			err := wsjson.Write(context.Background(), c.conn, map[string]interface{}{
				"action": definitions.GetMessageAction,
			})
			if err != nil {
				// server responded to our close message acknowledging it
				if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
					return
				}
				log.Panicln(err)
			}

			var readJson map[string]interface{}
			err = wsjson.Read(context.Background(), c.conn, &readJson)
			if err != nil {
				// server responded to our close message acknowledging it
				if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
					return
				}
				log.Panicln(err)
			}

			resultBytes, err := json.Marshal(readJson["result"])
			if err != nil {
				log.Panicln(err)
			}

			// Unmarshal the JSON into our struct
			err = json.Unmarshal(resultBytes, &result)
			if err != nil {
				log.Panicln(err)
			}
		} else {
			ticker := time.NewTicker(time.Millisecond * messagePollingMilliseconds)
			timeout := time.NewTimer(time.Second * messageTimeoutSeconds)
			tickerChannel := ticker.C
			timeoutChannel := timeout.C
			select {
			case <-timeoutChannel:
				log.Panicln("timeout")
			case <-tickerChannel:
			}
			resp, err := GetRequest(fmt.Sprintf("%s/protocols/%s/messages?isFor=%s&all=true", c.host, c.protocolId, c.id))
			if err != nil {
				log.Panicln(err)
			}

			respBodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Panicln(err)
			}
			defer resp.Body.Close()

			err = json.Unmarshal(respBodyBytes, &result)
			if err != nil {
				log.Panicln(err)
			}
		}

		resultMessages := result.Messages
		for i := range resultMessages {
			msgPayload := resultMessages[i]["payload"].(map[string]interface{})
			messageBytes, err := base64.StdEncoding.DecodeString(msgPayload["bytes"].(string))
			if err != nil {
				log.Panicln(err)
			}

			var incomingMsg messages.Message
			err = incomingMsg.UnmarshalBinary(messageBytes)
			if err != nil {
				log.Panicln(err)
			}
			c.incoming <- &incomingMsg
			if c.waitForIncomingMessages {
				c.waitForIncomingMessagesChan <- struct{}{}
			}
		}
	}
}

func (c *CapsuleCommunicator) SendMessages(doneChan chan struct{}, useWebSockets bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in func for SendMessages: %v\n", r)
			debug.PrintStack()
		}
		doneChan <- struct{}{}
	}()
	for {
		select {
		case <-c.done:
			return
		case out := <-c.outgoing:
			if c.waitForIncomingMessages {
				<-c.waitForIncomingMessagesChan
			}
			data, err := out.MarshalBinary()
			if err != nil {
				log.Panicln(err)
			}
			encodedBytes := base64.StdEncoding.EncodeToString(data)
			msgMap := map[string]interface{}{
				"bytes": encodedBytes,
			}
			body := map[string]interface{}{
				"payload": msgMap,
				"isFrom":  c.id,
				"isFor":   c.otherId,
			}
			if useWebSockets {
				err = wsjson.Write(context.Background(), c.conn, map[string]interface{}{
					"action": definitions.PostMessageAction,
					"body":   body,
				})
				if err != nil {
					log.Panicln(err)
				}
			} else {
				reqBody, err := json.Marshal(body)
				if err != nil {
					log.Panicln(err)
				}
				resp, err := PostRequest(fmt.Sprintf("%s/protocols/%s/messages", c.host, c.protocolId), bytes.NewBuffer(reqBody))
				if err != nil {
					log.Panicln(err)
				}
				// just reading response for purpose of keep-alive to take effect
				_, err = io.Copy(io.Discard, resp.Body)
				if err != nil {
					log.Printf("Error reading response body: %v\n", err)
				}
				defer resp.Body.Close()
			}
		}
	}
}

func beginsWith(base, pre string) bool {
	return len(base) >= len(pre) && base[:len(pre)] == pre
}

func (c *CapsuleCommunicator) Start(protocolId string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	useWebSockets := beginsWith(c.host, "ws")
	if useWebSockets {
		var err error
		c.conn, _, err = websocket.Dial(ctx, fmt.Sprintf("%s/ws/protocols/%s?isFor=%s", c.host, protocolId, c.id), nil)
		if err != nil {
			return err
		}
		c.conn.SetReadLimit(1024 * 1024) // 1MB
	}

	go c.SendMessages(c.sendMessagesDoneChan, useWebSockets)
	go c.GetMessages(c.getMessagesDoneChan, useWebSockets)
	return nil
}

func (c CapsuleCommunicator) Send(msg *messages.Message) error {
	c.outgoing <- msg
	return nil
}

func (c CapsuleCommunicator) Incoming() <-chan *messages.Message {
	return c.incoming
}

func (c CapsuleCommunicator) Done() {
	c.done <- struct{}{}
	c.done <- struct{}{}
	<-c.sendMessagesDoneChan

	if c.conn != nil {
		err := c.conn.Close(websocket.StatusNormalClosure, "client finished")
		if err != nil {
			log.Println(err)
		}
	}
}

func (c CapsuleCommunicator) Timeout() time.Duration {
	return 15 * time.Second
}
