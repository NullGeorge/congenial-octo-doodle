package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	switch os.Args[1] {
	case "run":
		fmt.Println("knockd-agent: daemon is not implemented yet")
	case "status":
		fmt.Println("knockd-agent: status is not implemented yet")
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("usage: knockd-agent <run|status>")
}
