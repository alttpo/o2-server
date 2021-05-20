package main

import (
	"bytes"
	"github.com/alttpo/o2-server/p3"
	"google.golang.org/protobuf/proto"
	"time"
)

func processProtocol03(message UDPMessage, buf *bytes.Buffer) (err error) {
	// parse message:
	gm := &p3.GroupMessage{}
	err = proto.Unmarshal(buf.Bytes(), gm)
	if err != nil {
		return
	}

	// trim whitespace and convert to lowercase for key lookup:
	group := gm.GetGroup()
	groupKey := calcGroupKey(group)
	clientGroup := findGroupOrCreate(groupKey)

	// create a key that represents the client from the received address:
	addr := message.ReceivedFrom
	clientKey := ClientKey{
		Port: addr.Port,
		Zone: addr.Zone,
	}
	copy(clientKey.IP[:], addr.IP)

	client, ci := findClientOrCreate(clientGroup, clientKey, addr, group, groupKey)

	// update client's sector:
	client.Sector = gm.PlayerInSector

	// prepare the message for rebroadcast:
	gm.PlayerIndex = uint32(ci)
	gm.ServerTime = time.Now().UnixNano()

	if gm.GetJoinGroup() != nil {
		// join player to group:
		networkMetrics.ReceivedBytes(len(message.Envelope), "p3:joinGroup", clientGroup, client)

		// respond:
		var rspBytes []byte
		rspBytes, err = proto.Marshal(gm)
		if err != nil {
			return
		}

		// send message back to client:
		_, err = conn.WriteToUDP(rspBytes, &client.UDPAddr)
		if err != nil {
			return
		}
		networkMetrics.SentBytes(len(rspBytes), "p3:joinGroup", clientGroup, client)
	} else if ba := gm.GetBroadcastAll(); ba != nil {
		// broadcast a message to all players:
		networkMetrics.ReceivedBytes(len(message.Envelope), "p3:broadcastAll", clientGroup, client)

		// construct the broadcast message:
		var rspBytes []byte
		rspBytes, err = proto.Marshal(gm)
		if err != nil {
			return
		}

		// iterate through all clients:
		for i := range clientGroup.Clients {
			c := &clientGroup.Clients[i]
			if !c.IsAlive {
				continue
			}
			if c == client {
				continue
			}

			// send message to this client:
			_, err = conn.WriteToUDP(rspBytes, &c.UDPAddr)
			if err != nil {
				return
			}

			networkMetrics.SentBytes(len(rspBytes), "p3:broadcastAll", clientGroup, client)

			//log.Printf("[group %s] (%v) sent message to (%v)\n", groupKey, client, other)
		}
	} else if bs := gm.GetBroadcastSector(); bs != nil {
		networkMetrics.ReceivedBytes(len(message.Envelope), "p3:broadcastSector", clientGroup, client)

		// construct the broadcast message:
		var rspBytes []byte
		rspBytes, err = proto.Marshal(gm)
		if err != nil {
			return
		}

		// iterate through all clients:
		for i := range clientGroup.Clients {
			c := &clientGroup.Clients[i]
			if !c.IsAlive {
				continue
			}
			if c == client {
				continue
			}
			// player must be in sector being broadcast to:
			if c.Sector != bs.TargetSector {
				continue
			}

			// send message to this client:
			_, err = conn.WriteToUDP(rspBytes, &c.UDPAddr)
			if err != nil {
				return
			}

			networkMetrics.SentBytes(len(rspBytes), "p3:broadcastSector", clientGroup, client)

			//log.Printf("[group %s] (%v) sent message to (%v)\n", groupKey, client, other)
		}
	}

	return
}
