package main

import (
	"bytes"
	"encoding/binary"
	"log"
)

func processProtocol01(message UDPMessage, buf *bytes.Buffer) (fatalErr error) {
	var err error
	var group string
	group, err = readTinyString(buf)
	if err != nil {
		log.Print(err)
		return
	}

	var name string
	name, err = readTinyString(buf)
	if err != nil {
		log.Print(err)
		return
	}

	var clientType uint8
	if err := binary.Read(buf, binary.LittleEndian, &clientType); err != nil {
		log.Print(err)
		return
	}

	// TODO: emit Index back to clients
	payload := buf.Bytes()

	buf = nil

	// trim whitespace and convert to lowercase for key lookup:
	groupKey := calcGroupKey(group)
	clientGroup := findGroupOrCreate(groupKey)

	// create a key that represents the client from the received address:
	addrPort := message.ReceivedFrom
	client, ci := findClientOrCreate(clientGroup, addrPort, group, groupKey)

	// record number of bytes received:
	networkMetrics.ReceivedBytes(len(message.Envelope), "broadcast", clientGroup, client)

	// broadcast message received to all other clients:
	for i := range clientGroup.Clients {
		c := &clientGroup.Clients[i]
		// don't echo back to client received from:
		if c == client {
			//log.Printf("(%v) skip echo\n", otherKey.IP)
			continue
		}
		if !c.IsAlive {
			continue
		}

		// construct message:
		buf = &bytes.Buffer{}
		header := uint16(25887)
		binary.Write(buf, binary.LittleEndian, &header)
		protocol := byte(0x01)
		buf.WriteByte(protocol)

		// protocol packet:
		buf.WriteByte(uint8(len(group)))
		buf.WriteString(group)
		buf.WriteByte(uint8(len(name)))
		buf.WriteString(name)
		index := uint16(ci)
		binary.Write(buf, binary.LittleEndian, &index)
		buf.WriteByte(clientType)
		buf.Write(payload)

		// send message to this client:
		bufBytes := buf.Bytes()
		_, fatalErr = conn.WriteToUDPAddrPort(bufBytes, c.AddrPort)
		if fatalErr != nil {
			return
		}
		networkMetrics.SentBytes(len(bufBytes), "broadcast", clientGroup, client)
		buf = nil
		//log.Printf("[group %s] (%v) sent message to (%v)\n", groupKey, client, other)
	}

	return
}
