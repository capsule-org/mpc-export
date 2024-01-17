package network

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/capsule-org/multi-party-sig/pkg/party"
	"github.com/capsule-org/multi-party-sig/pkg/protocol"

	"nhooyr.io/websocket"
)

type JSFunc interface {
	Invoke(args ...any) any
}

// HandlerLoop blocks until the handler has finished. The result of the execution is given by Handler.Result().
func HandlerLoop(id party.ID, h protocol.Handler, network *Network, protocolId string, statusFunc JSFunc, useWebSocket bool) error {
	nextChan := make(chan struct{}, 1)
	doneChan := make(chan struct{}, 1)
	wsDoneReadChan := make(chan struct{}, 1)
	wsDoneReadChan <- struct{}{}
	var conn *websocket.Conn

	if useWebSocket {
		var err error
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		conn, _, err = websocket.Dial(ctx, fmt.Sprintf("%s/ws/protocols/%s?isFor=%s", network.Host, protocolId, id), nil)
		if err != nil {
			return err
		}
		conn.SetReadLimit(1024 * 1024) // 1MB

		defer func() {
			err = conn.Close(websocket.StatusNormalClosure, "client finished")
			if err != nil {
				log.Println(err)
			}
		}()
	}

	pendingWriteChan := make(chan struct{}, 10)
	pendingWrites := 0
	for {
		msgMapChan, err := network.Next(string(id), protocolId, nextChan, doneChan, conn, wsDoneReadChan)
		if err != nil {
			return err
		}
		select {

		// outgoing messages
		case msg, ok := <-h.Listen():
			if !ok {
				for i := 0; i < pendingWrites; i++ {
					<-pendingWriteChan
				}
				<-network.Done(string(id))
				// the channel was closed, indicating that the protocol is done executing.
				doneChan <- struct{}{}
				return nil
			}
			// convert message struct to map so network layer can handle it
			var msgMap map[string]interface{}
			data, err := json.Marshal(msg)
			if err != nil {
				return err
			}
			json.Unmarshal(data, &msgMap)

			pendingWrites++
			go network.Send(protocolId, msgMap, conn, pendingWriteChan)

		// incoming messages
		case msgMap := <-msgMapChan:
			var msg protocol.Message
			data, err := json.Marshal(msgMap)
			if err != nil {
				return err
			}
			json.Unmarshal(data, &msg)

			h.Accept(&msg)
			if statusFunc != nil {
				statusFunc.Invoke()
			}
		}
	}
}
