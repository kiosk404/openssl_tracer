/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2022/5/17
**/
package uprobe_tracing

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type AttachType int64

const (
	COLORRESET  = "\033[0m"
	COLORRED    = "\033[31m"
	COLORGREEN  = "\033[32m"
	COLORYELLOW = "\033[33m"
	COLORBLUE   = "\033[34m"
	COLORPURPLE = "\033[35m"
	COLORCYAN   = "\033[36m"
	COLORWHITE  = "\033[37m"
)

const (
	PROBE_ENTRY AttachType = iota
	PROBE_RET
)

const MAX_DATA_SIZE = 1024 * 4

type SSLDataEvent struct {
	EventType   int64
	TimestampNs uint64
	Pid         uint32
	Tid         uint32
	Data        [MAX_DATA_SIZE]byte
	DataLen     int32
	Comm        [16]byte
	Fd          uint32
}

func (event *SSLDataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &event.EventType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &event.TimestampNs); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &event.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &event.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &event.Data); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &event.DataLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &event.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &event.Fd); err != nil {
		return
	}

	return nil
}

func (event *SSLDataEvent) String() string {
	var perfix, connInfo string
	switch AttachType(event.EventType) {
	case PROBE_ENTRY:
		connInfo = fmt.Sprintf("%sRecived %d%s bytes", COLORGREEN, event.DataLen, COLORRESET)
		perfix = COLORGREEN
	case PROBE_RET:
		connInfo = fmt.Sprintf("%sSend %d%s bytes", COLORPURPLE, event.DataLen, COLORRESET)
		perfix = COLORPURPLE
	default:
		connInfo = fmt.Sprintf("%sUNKNOW_%d%s", COLORRED, event.EventType, COLORRESET)
	}
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Payload:\n%s%s%s",
		event.Pid, event.Comm, event.Tid, connInfo, perfix, string(event.Data[:event.DataLen]), COLORRESET)
	return s
}