package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

func main() {
	// Make a channel for results and start listening
	fmt.Println("HOLA MUCHACHOS")
	// var wg sync.WaitGroup
	// entriesCh := make(chan *mdns.ServiceEntry, 4)
	// wg.Add(1)
	// go func() {
	// 	defer wg.Done()
	// 	for entry := range entriesCh {
	// 		fmt.Printf("Got new entry: %v\n", entry)
	// 	}
	// 	fmt.Printf("anything")
	// }()
	// err := mdns.Lookup("_obelisksc1._tcp", entriesCh)
	// if err != nil {
	// 	fmt.Println("LOLOLOLOL: ", err)
	// }
	// // Start the lookup

	// wg.Wait()
	// close(entriesCh)
	// Discover all services on the network (e.g. _workstation._tcp)
	// --------------------------
	// resolver, err := zeroconf.NewResolver(nil)
	// if err != nil {
	// 	log.Fatalln("Failed to initialize resolver:", err.Error())
	// }

	// entries := make(chan *zeroconf.ServiceEntry)
	// // wg.Add(1)
	// go func(results <-chan *zeroconf.ServiceEntry) {
	// 	// defer wg.Done()
	// 	for entry := range results {
	// 		log.Println(entry)
	// 	}
	// 	log.Println("No more entries.")
	// }(entries)

	// ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	// defer cancel()
	// err = resolver.Browse(ctx, "_obelisksc1._tcp", "local.", entries)
	// if err != nil {
	// 	log.Fatalln("Failed to browse:", err.Error())
	// }

	// <-ctx.Done()

	// UDP SHIT
	addr := &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	}
	conn, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		panic("fuck your mom if you want to fuck")
	}
	defer conn.Close()
	r := bufio.NewReader(conn)

	for {

		line, _, err := r.ReadLine()
		_, remoteAddr, err := conn.ReadFromUDP(line)
		if remoteAddr != nil {
			fmt.Printf("%+v\n", remoteAddr)
			fmt.Println("hi", string(line))
		}
		if err != nil {
			fmt.Println("LOLOLOL", err)
			return
		}

		contains := strings.Contains(string(line), "Obelisk")
		if contains {
			// fmt.Println("ip from ", ip.String())
			fmt.Println("FOUND OBELISK")
			if strings.Contains(string(line), "SC1") {
				fmt.Println("FOUND SC1")
			}
		}
	}
}
