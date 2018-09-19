package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// PortCGMiner is a const that defines the default api-port for CGMiner.
	PortCGMiner = 4028
	// PortSSH is a const that defines the default port for SSH.
	PortSSH = 22
	// PortWeb is a const that defines the webclient on port 80.
	PortWeb = 80
)

// Define errors
const (
	errUnmarshal = "Error Unmarshalling API Response"
)

// Obelisk defines the fields for a found unit.
type Obelisk struct {
	IP       net.IP `json:"ip"`
	Model    string `json:"model"`
	MAC      string `json:"mac"`
	Firmware string `json:"firmwareVersion"`
}

// ScanJob is a single job for the Prediction Process
type ScanJob struct {
	IP net.IP
}

// APIResponseInfo is an open response for the Obelisk miner. We use this
// endpoint to identify the Obelisk.
type APIResponseInfo struct {
	MacAddress string `json:"macAddress"`
	IP         string `json:"ipAddress"`
	Model      string `json:"model"`
	Vendor     string `json:"vendor"`
	Firmware   string `json:"firmwareVersion,omitempty"`
}

// SubnetFromInterface finds the first IPv4 address that is non-loopback. This
// should be the IP of the subnet.
func SubnetFromInterface() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if !ip.IsLoopback() && ip.To4() != nil {
				return ip, nil
			}
		}
	}
	return nil, nil
}

// Scan will go through an ip range and try to ping default ASIC ports.
func Scan(subnet string, timeout time.Duration) ([]*Obelisk, error) {
	var (
		parsedIP net.IP
		ipnet    *net.IPNet
		err      error
	)
	// Parse the subnet string into an IP
	if !strings.Contains(subnet, "/") {
		parsedIP = net.ParseIP(subnet)
		if parsedIP == nil {
			return nil, errors.New("Invalid IP address")
		}
	} else {
		parsedIP, ipnet, err = net.ParseCIDR(subnet)
		if err != nil {
			return nil, err
		}
	}
	var miners []*Obelisk
	start := time.Now()
	logrus.Infof("Scanning for Obelisks on %s with TCP...", parsedIP)

	if ipnet == nil {
		logrus.Infof("Only single ip found - attempting to identify device %s\n", parsedIP)
		m, err := identify(parsedIP, timeout)
		if err != nil {
			logrus.Error(err)
			return nil, err
		}
		if m != nil {
			miners = append(miners, m)
		}
	}
	logrus.Infof("Valid subnet - will search through ip range: %s\n", ipnet)

	var wg sync.WaitGroup
	jobChan := make(chan ScanJob)
	// Sets default works to 256, which is the space for one-byte (0-255)
	defaultWorkers := 256
	wg.Add(defaultWorkers)
	// Spin up workers to limit the number of spawned connections
	for i := 0; i < defaultWorkers; i++ {
		// Start job processor
		go func() {
			defer wg.Done()
			for job := range jobChan {
				m, err := identify(job.IP, timeout)
				if err != nil {
					logrus.Error(err)
					return
				}
				if m != nil {
					miners = append(miners, m)
				}
			}
		}()
	}
	countJobs := 0
	// Loop through the ip range and inc(ip) each time
	for ip := parsedIP.Mask(ipnet.Mask); ipnet.Contains(ip); ip = inc(ip) {
		countJobs++
		jobChan <- ScanJob{
			IP: ip,
		}
	}
	close(jobChan)
	wg.Wait()
	logrus.Infof("Took %v to scan %d ips.\n", time.Since(start), countJobs)
	return miners, nil
}

func inc(x net.IP) net.IP {
	ip := make(net.IP, len(x))
	copy(ip, x)
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
	return ip
}

func hostPort(host net.IP, port int) string {
	return net.JoinHostPort(host.String(), strconv.Itoa(port))
}

// isAnyOpen is a helper function that checks a slice of ports. If a single port
// is open, it returns true.
func isAnyOpen(host net.IP, ports []int, timeout time.Duration) bool {
	doneChan := make(chan bool, len(ports))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, p := range ports {
		hp := hostPort(host, p)
		go func(addr string) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
			}
			doneChan <- err == nil
		}(hp)
	}
	success := false
	for range ports {
		if <-doneChan && !success {
			success = true
			cancel()
		}
	}
	return success
}

func identify(ip net.IP, timeout time.Duration) (*Obelisk, error) {
	portsToCheck := []int{PortWeb}
	isPortOpen := isAnyOpen(ip, portsToCheck, timeout)
	if isPortOpen {
		// Confirmed that CGMiner is open. Now we have to identify if this is an Obelisk device.
		endpoint := fmt.Sprintf("http://%s/api/info", ip)
		resp, err := http.Get(endpoint)
		if err != nil {
			return nil, nil
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var info APIResponseInfo
		err = json.Unmarshal(body, &info)
		if err != nil {
			return nil, nil
		}
		o := &Obelisk{
			IP:       ip,
			MAC:      info.MacAddress,
			Model:    info.Model,
			Firmware: info.Firmware,
		}
		return o, nil
	}
	return nil, nil
}
