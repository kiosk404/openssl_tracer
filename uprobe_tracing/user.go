/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2022/5/17
**/
package uprobe_tracing

import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	obj, err := ioutil.ReadFile(cannonicalName)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
	}
	return obj, nil
}

func PerfEventReader(errChan chan error, em *ebpf.Map, ctx context.Context) {
	rd, err := perf.NewReader(em, os.Getpagesize()*64)
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(), err)
		return
	}

	defer rd.Close()
	for {
		//判断ctx是不是结束
		select {
		case _ = <- ctx.Done():
			logrus.Printf("readEvent received close signal from context.Done.")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			errChan <- fmt.Errorf("reading from perf event reader: %s", err)
			return
		}

		if record.LostSamples != 0 {
			logrus.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		var sslEvent = &SSLDataEvent{}
		err = sslEvent.Decode(record.RawSample)
		if err != nil {
			log.Printf("decode error:%v", err)
			continue
		}

		// 打印数据
		str := sslEvent.String()
		fmt.Println(str)
	}
}