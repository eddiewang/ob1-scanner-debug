# ob1-scanner

ob1-scanner is a small library used to help find Obelisk miners.

## Usage

To compile this application, you must have Golang installed.

```
go get gitlab.com/NebulousLabs/ob1-scanner/...
go install
ob1-scanner scan [subnet]
```

## Quickstart

Find the subnet you want to scan on (e.g. 192.168.0.1/24) and pass that as the arguement to the `scan` command like so:

```
ob1-scanner scan 192.168.0.1/24
```

The command above scans the ip range from 192.169.0.0 - 192.168.0.255.

You can also pass a timeout:

```
ob1-scanner scan 192.168.0.1/24 -t 5s
```

The timeout flag sets how long the scanner should wait for a response from the IP before moving on. The default setting is 2 seconds.
