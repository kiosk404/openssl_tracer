/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2022/5/17
**/
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"github.com/cilium/ebpf/rlimit"
	"github.com/ehids/ebpfmanager"
	"github.com/kiosk404/openssl_tracer/uprobe_tracing"
	"github.com/sirupsen/logrus"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var pid int

func init() {
	flag.IntVar(&pid, "pid", 0, "input tracing pid")
}


func main() {
	var mgr *manager.Manager
	var option manager.Options

	flag.Parse()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFunc := context.WithCancel(context.TODO())

	mgr = uprobe_tracing.EBPFManager()
	option = uprobe_tracing.EBPFManagerOption(pid)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// fetch ebpf assets
	byteBuf, err := uprobe_tracing.Asset("bpf/openssl_trace.bpf.o")
	if err != nil {
		logrus.Fatalln(err)
	}

	// Initialize the manager
	if err := mgr.InitWithOptions(bytes.NewReader(byteBuf), option); err != nil {
		logrus.Fatal(err)
	}
	//if err := mgr.Init(bytes.NewReader(byteBuf)); err != nil {
	//	logrus.Fatalln(err)
	//}

	// Start the manager
	if err := mgr.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	//SSLDumpEventsMap 与解码函数映射
	SSLDumpEventsMap, found, err := mgr.GetMap("tls_events")
	if err != nil {
		logrus.Fatalln(err)
	}
	if !found {
		logrus.Fatalln("cant found map:tls_events")
	}

	var errChan = make(chan error)
	go uprobe_tracing.PerfEventReader(errChan, SSLDumpEventsMap, ctx)

	select {
	case <- stopper:
		fmt.Println("stop capture")
		cancelFunc()
	case err := <- errChan:
		logrus.Error(err)
	}

	logrus.Println("close all")
	// Close the manager
	if err := mgr.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}