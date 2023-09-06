package main

import (
	"testing"
	"time"
)

func TestMainFunc(t *testing.T) {
	go main()
	tm := time.NewTimer(time.Second * 30)
	<-tm.C
	tm.Stop()
}
