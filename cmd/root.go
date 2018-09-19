package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gitlab.com/NebulousLabs/ob1-scanner/scanner"
	"golang.org/x/crypto/ssh"
)

// exit codes
// inspired by sysexits.h
const (
	exitCodeGeneral = 1  // Not in sysexits.h, but is standard practice.
	exitCodeUsage   = 64 // EX_USAGE in sysexits.h
)

// ScanConfig contains the flags for the scan command
type ScanConfig struct {
	subnet  string
	timeout string
}

type UpgradeConfig struct {
	timeout      string
	firmwarePath string
	host         string
	json         bool
}

var FlagJSON bool

// JSONMachines defines the JSON payload for scan func
type JSONMachines struct {
	Status  bool               `json:"status"`
	Payload []*scanner.Obelisk `json:"payload"`
}

// ScanConf is a config for scan
var ScanConf ScanConfig

var rootCmd = &cobra.Command{
	Use:   "ob1-scanner",
	Short: "ob1-scanner is a quick Obelisk scanner tool",
	Run:   startDaemonCmd,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of ob1-scanner",
	Long:  "Prints the current binary version of ob1-scanner you are using.",
	Run: func(cmd *cobra.Command, _ []string) {
		logrus.Infof("ob1-scanner Version 0.0.1 %s / %s\n", runtime.GOOS, runtime.GOARCH)
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan [subnet]",
	Short: "Scans a subnet and returns identified machines.",
	Long:  "Uses a netscan tool to scan a subnet, look for API ports, and try to identify a recognized Obelisk.",
	Run:   wrap(scanHandler),
}

var mdnsCmd = &cobra.Command{
	Use:   "mdns",
	Short: "Starts a mDNS client and watches for Obelisk packets.",
	Long:  "Starts a UDP Multicast Listener, and specifically watches for Obelisk packets to identify the packet source.",
	Run:   wrap(mdnsHandler),
}

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrades an Obelisk with passed in firmware.",
	Long:  "SSHs into the Obelisk, and attempts to upgrade the new firmware.",
	Run:   wrap(upgradeHandler),
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(mdnsCmd)
	rootCmd.AddCommand(upgradeCmd)
	scanCmd.PersistentFlags().StringVarP(&ScanConf.timeout, "timeout", "t", "2s", "timeout for port checks and RPC calls")
	// Figure out subnet
	var ipString string
	ip, err := scanner.SubnetFromInterface()
	if err != nil {
		logrus.Info("Error scanning interface: ", err)
	}
	if ip == nil {
		logrus.Info("Could not auto-configure subnet, setting to 192.168.0.1")
		ipString = "192.168.0.1"
	} else {
		ipString = fmt.Sprintf("%s/%s", ip.String(), "24")
	}
	scanCmd.PersistentFlags().StringVarP(&ScanConf.subnet, "subnet", "i", ipString, "timeout for port checks and RPC calls")
	rootCmd.PersistentFlags().BoolVarP(&FlagJSON, "json", "j", false, "set json output")
}

// Execute is calls the root command from cobra
func Execute() {
	// Runs the root cmd, which is startDaemonCmd in our case. Will exit(64) if
	// flags cannot be parsed.
	if err := rootCmd.Execute(); err != nil {
		os.Exit(exitCodeUsage)
	}

}

func startDaemonCmd(cmd *cobra.Command, _ []string) {
	cmd.UsageFunc()(cmd)
}

func upgradeHandler() {
	cmd := os.Args[1]
	hosts := os.Args[2:]

	results := make(chan string, 10)
	timeout := time.After(10 * time.Second)

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "22"
	}

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password("obelisk"),
		},
	}

	for _, hostname := range hosts {
		go func(hostname string, port string) {
			results <- executeCmd(cmd, hostname, port, config)
		}(hostname, port)
	}

	for i := 0; i < len(hosts); i++ {
		select {
		case res := <-results:
			fmt.Print(res)
		case <-timeout:
			fmt.Println("Timed out!")
			return
		}
	}
}

func executeCmd(command, hostname string, port string, config *ssh.ClientConfig) string {
	conn, _ := ssh.Dial("tcp", fmt.Sprintf("%s:%s", hostname, port), config)
	session, _ := conn.NewSession()
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Run(command)

	return fmt.Sprintf("%s -> %s", hostname, stdoutBuf.String())
}

func scanHandler() {
	if FlagJSON {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	}
	timeout, err := time.ParseDuration(ScanConf.timeout)
	if err != nil {
		logrus.Error(err)
		os.Exit(exitCodeUsage)
	}
	machines, err := scanner.Scan(ScanConf.subnet, timeout)
	if err != nil {
		logrus.Error(err)
		os.Exit(exitCodeUsage)
	}
	if FlagJSON {
		j := &JSONMachines{
			Status:  true,
			Payload: machines,
		}
		b, err := json.Marshal(j)
		if err != nil {
			logrus.Error(err)
			return
		}
		fmt.Print(string(b))
	} else {
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "\n%s\t%s\t%s\t", "IP", "MAC Address", "Model")
		fmt.Fprintf(tw, "\n%s\t%s\t%s\t\n", "----", "----", "----")

		for _, v := range machines {
			fmt.Fprintf(tw, "%v\t%v\t%v\n", v.IP, v.MAC, v.Model)
		}
		tw.Flush()
	}
}

func mdnsHandler() {
	if FlagJSON {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	}
	addr := &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	}
	logrus.Info("Starting UDP Multicast Listener...")
	conn, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		logrus.Error(err)
	}
	for {
		b := make([]byte, 100)
		_, remoteAddr, err := conn.ReadFromUDP(b)
		if err != nil {
			logrus.Error(err)
			return
		}

		udpString := string(b)
		contains := strings.Contains(udpString, "Obelisk")
		if contains {
			machine := &scanner.Obelisk{
				IP:    remoteAddr.IP,
				MAC:   "Unknown/mDNS",
				Model: "Unknown",
			}
			if strings.Contains(udpString, "SC1") {
				machine.Model = "SC1"
			} else if strings.Contains(udpString, "DCR1") {
				machine.Model = "DCR1"
			}
			if FlagJSON {
				j := &JSONMachines{
					Status:  true,
					Payload: []*scanner.Obelisk{machine},
				}
				b, err := json.Marshal(j)
				if err != nil {
					logrus.Error(err)
					return
				}
				fmt.Print(string(b))
			} else {
				tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintf(tw, "\n%s\t%s\t%s\t", "IP", "MAC Address", "Model")
				fmt.Fprintf(tw, "\n%s\t%s\t%s\t\n", "----", "----", "----")

				fmt.Fprintf(tw, "%v\t%v\t%v\n", machine.IP, machine.MAC, machine.Model)
				tw.Flush()
			}
		}
	}
}

// wrap wraps a generic command with a check that the command has been
// passed the correct number of arguments. The command must take only strings
// as arguments.
func wrap(fn interface{}) func(*cobra.Command, []string) {
	fnVal, fnType := reflect.ValueOf(fn), reflect.TypeOf(fn)
	if fnType.Kind() != reflect.Func {
		panic("Wrapped func has wrong signature")
	}
	for i := 0; i < fnType.NumIn(); i++ {
		if fnType.In(i).Kind() != reflect.String {
			panic("Wrapped func has wrong input type signature")
		}
	}

	return func(cmd *cobra.Command, args []string) {
		if len(args) != fnType.NumIn() {
			cmd.UsageFunc()(cmd)
			os.Exit(exitCodeUsage)
		}
		argVals := make([]reflect.Value, fnType.NumIn())
		for i := range args {
			argVals[i] = reflect.ValueOf(args[i])
		}
		fnVal.Call(argVals)
	}
}