package main

import (
	"context"
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
	"math/rand"
	"encoding/hex"
	"encoding/json"
	"strings"

	quic "github.com/quic-go/quic-go"
)

var outputFile *os.File
var jsonFile *os.File
var suricataOutFile *os.File
var timeDelay *int
var maxDelay int = 10000
var number_of_strategies int = 10
var logMu sync.Mutex

type resultJSON struct {
	Timestamp        string   `json:"timestamp"`
	Domain           string   `json:"domain"`
	MutationID       int      `json:"mutation_id"`
	Original         string   `json:"original"`
	OriginalResponse string   `json:"original_response"`
	Precursor        []string `json:"precursor"` // hex-encoded list of packets sent before the final mutated packet
	Mutated          string   `json:"mutated"`
	Response         string   `json:"response"`
}

type suricataLog struct {
	Timestamp  string `json:"timestamp"`
	Domain     string `json:"domain"`
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	SrcPort    int    `json:"src_port"`
	MutationID int    `json:"mutation_id"`
	DCID       string `json:"dcid"`
}

// safePrintf replaces writef (or call this *inside* writef).
func safePrintf(format string, a ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Printf(format, a...)
}

// readResponse pulls one packet (up to 4 kB) – returns nil on timeout.
func readResponse(conn net.PacketConn) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		// ignore timeouts
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil, nil
		}
		return nil, err
	}
	return buf[:n], nil
}


// logResult prints the full mutation block *without* interleaving and writes JSON.
// For precursor strategies, pass the ordered list of precursor packets (hex) via precursors.
func logResult(domain string, mutation int, original, originalResponse []byte, precursors [][]byte, mutated, response []byte, srcPort int) {
	logMu.Lock()
	defer logMu.Unlock()

	if outputFile == nil || jsonFile == nil {
		fmt.Fprintln(os.Stderr, "Output files not initialized")
		return
	}

	// Write to output.txt (human-readable)
	fmt.Fprintf(outputFile, "Domain: %s\n", domain)
	fmt.Fprintf(outputFile, "MutationID: %d\n", mutation)

	// Baseline
	fmt.Fprintf(outputFile, "Original (%d B): %x\n", len(original), original)
	fmt.Fprintf(outputFile, "\nOriginal Response (%d B): %x\n", len(originalResponse), originalResponse)

	// Precursors (if any)
	if len(precursors) > 0 {
		fmt.Fprintf(outputFile, "\nPrecursor Packets Sent Before (%d):\n", len(precursors))
		for i, p := range precursors {
			fmt.Fprintf(outputFile, "  Precursor[%d] (%d B): %x\n", i, len(p), p)
		}
	}

	// Final mutated + response
	fmt.Fprintf(outputFile, "\nFinal Mutated  (%d B): %x\n", len(mutated), mutated)
	fmt.Fprintf(outputFile, "\nFinal Response (%d B): %x\n\n", len(response), response)

	// Build JSON entry (hex-encode everything)
	precursorHex := make([]string, 0, len(precursors))
	for _, p := range precursors {
		precursorHex = append(precursorHex, hex.EncodeToString(p))
	}
	entry := resultJSON{
		Timestamp:        time.Now().Format(time.RFC3339Nano),
		Domain:           domain,
		MutationID:       mutation,
		Original:         hex.EncodeToString(original),
		OriginalResponse: hex.EncodeToString(originalResponse),
		Precursor:        precursorHex,
		Mutated:          hex.EncodeToString(mutated),
		Response:         hex.EncodeToString(response),
	}
	json.NewEncoder(jsonFile).Encode(entry)

	// Extract DCID from final mutated for Suricata-style record
	var dcid string
	if len(mutated) > 6 {
		dcidLen := int(mutated[5])
		if len(mutated) >= 6+dcidLen {
			dcid = hex.EncodeToString(mutated[6 : 6+dcidLen])
		}
	}

	// Resolve IP/port from domain
	ipAddr, err := net.ResolveUDPAddr("udp", domain+":443")
	if err != nil {
		ipAddr = &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 443}
	}

	// Write Suricata-style log (unchanged schema, now tied to final mutated/DCID)
	suriEntry := suricataLog{
		Timestamp:  time.Now().Format(time.RFC3339Nano),
		Domain:     domain,
		IP:         ipAddr.IP.String(),
		Port:       ipAddr.Port,
		SrcPort:    srcPort,
		MutationID: mutation,
		DCID:       dcid,
	}
	json.NewEncoder(suricataOutFile).Encode(suriEntry)
}



// WorkItem represents a single fuzzing task
type WorkItem struct {
	Domain     string
	//RemoteAddr *net.UDPAddr
	//Original   []byte
	MutationID int
}

func main() {
	timeDelay = flag.Int("delay", 100, "Maximum random delay in milliseconds")
	outputPath := flag.String("out", "output.txt", "Output file")
	threadCount := flag.Int("threads", runtime.NumCPU()-1, "Number of worker threads")
	suricataPath := strings.Replace(*outputPath, ".txt", "_suricata.json", 1)
	flag.Parse()

	var err error
	outputFile, err = os.OpenFile(*outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer outputFile.Close()

	jsonPath := strings.Replace(*outputPath, ".txt", ".json", 1)
	jsonFile, err = os.OpenFile(jsonPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()

	suricataOutFile, err = os.OpenFile(suricataPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer suricataOutFile.Close()

	domains, err := loadDomains("domain.csv")
	if err != nil {
		log.Fatal(err)
	}

	mutations, err := loadMutations("input.csv")
	if err != nil {
		log.Fatal(err)
	}

	workQueue := make(chan WorkItem, 1000)
	var wg sync.WaitGroup

	if *threadCount < 1 {
		*threadCount = 1
	}
	writef("Spawning %d worker threads\n", *threadCount)
	for i := 0; i < *threadCount; i++ {
		wg.Add(1)
		go worker(workQueue, &wg)
	}

	for _, domain := range domains {
		// writef("Capturing packet for domain: %s\n", domain)
		// remoteAddr, original := captureInitialPacket(domain)
		// if original == nil {
		// 	writef("Failed to capture packet for domain: %s\n", domain)
		// 	continue
		// }
		for i := 0; i < 100; i++ {
			for id := 1; id <= number_of_strategies; id++ {
				if mutations[id] {
					workQueue <- WorkItem{
						Domain:     domain,
						MutationID: id,
					}
				}
			}
		}
	}

	close(workQueue)
	wg.Wait()
	writef("All work completed. Exiting.\n")
}

func captureInitialPacket(domain string) (*net.UDPAddr, []byte) {
	baseConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		writef("Error creating base connection: %v\n", err)
		return nil, nil
	}
	defer baseConn.Close()

	wrapped := &InterceptConn{
		PacketConn: baseConn,
		LogPackets: true,
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", domain+":443")
	if err != nil {
		writef("Error resolving address: %v\n", err)
		return nil, nil
	}

	keyLogFile, err := os.OpenFile("quic_tls_keys.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		writef("Failed to create key log file: %v\n", err)
		return nil, nil
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
		KeyLogWriter:       keyLogFile,
	}

	defer keyLogFile.Close()
	quicConf := &quic.Config{}

	_, _ = quic.Dial(context.Background(), wrapped, remoteAddr, tlsConf, quicConf)
	time.Sleep(2 * time.Second)

	pkt := wrapped.CaptureNextPacket()
	if pkt == nil {
		writef("No packet was captured for domain: %s\n", domain)
		return nil, nil
	}
	//writef("Captured QUIC packet (%d bytes)\n", len(pkt.Data))
 
	return remoteAddr, pkt.Data
}

func worker(workQueue <-chan WorkItem, wg *sync.WaitGroup) {
	defer wg.Done()
	for item := range workQueue {
		writef("Worker processing: %s (Mutation %d)\n", item.Domain, item.MutationID)

		remoteAddr, original := captureInitialPacket(item.Domain)
		if original == nil {
			writef("Failed to capture packet for domain: %s\n", item.Domain)
			continue
		}

		// var to store the original response
		var originalResponse []byte
		origConn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			safePrintf("Failed to open UDP socket for original: %v\n", err)
		} else {
			defer origConn.Close()

			_, err = origConn.WriteTo(original, remoteAddr)
			if err != nil {
				safePrintf("Failed to send original: %v\n", err)
			} else {
				resp, err := readResponse(origConn)
				if err != nil {
					safePrintf("Failed to read original response: %v\n", err)
				} else if resp != nil {
					// ✅ Save the response
					originalResponse = append([]byte(nil), resp...) // deep copy to avoid reuse issues
				}
			}
		}

		// Apply mutation
		mutationFunc := GetMutationFunc(item.MutationID)
		mutatations := mutationFunc(original)

		// we get back the muations which should now be a list of lists
		// we know execute all the mutations that we have 
		if item.MutationID <= 6 {
			for _, mutated := range mutatations.Buffers {

				mutConn, err := net.ListenPacket("udp", ":0")
				if err != nil {
					safePrintf("Failed to open UDP socket: %v\n", err)
					continue
				}

				delayMs := *timeDelay + rand.Intn(maxDelay+1)
				time.Sleep(time.Duration(delayMs) * time.Millisecond)

				if _, err = mutConn.WriteTo(mutated, remoteAddr); err != nil {
					safePrintf("Failed to send mutated: %v\n", err)
					_ = mutConn.Close()
					continue
				}

				if resp, err := readResponse(mutConn); err != nil {
					safePrintf("Failed to read response: %v\n", err)
				} else if resp != nil {
					localAddr := mutConn.LocalAddr().(*net.UDPAddr)
					logResult(item.Domain, item.MutationID, original, originalResponse, nil, mutated, resp, localAddr.Port)
				}

				_ = mutConn.Close()
			}
		} else {
			// Precursor strategies: send a SEQUENCE of packets over a single 5-tuple.
			// We will log the *final* mutated packet that yielded a response,
			// along with the ordered list of *all packets sent before it* (precursors).
			mutConn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				safePrintf("Failed to open UDP socket: %v\n", err)
				return
			}
			defer mutConn.Close()

			delayMs := *timeDelay + rand.Intn(maxDelay+1)
			time.Sleep(time.Duration(delayMs) * time.Millisecond)

			var lastResp []byte
			var lastMutated []byte
			lastIndex := -1

			// Track the entire send sequence so we can recover precursors later.
			// We deep-copy each buffer we send to avoid accidental reuse.
			sentSeq := make([][]byte, 0, len(mutatations.Buffers))

			for idx, mutated := range mutatations.Buffers {
				sentCopy := append([]byte(nil), mutated...)
				sentSeq = append(sentSeq, sentCopy)

				if _, err := mutConn.WriteTo(mutated, remoteAddr); err != nil {
					safePrintf("Failed to send mutated: %v\n", err)
					continue
				}

				resp, err := readResponse(mutConn)
				if err != nil {
					safePrintf("Failed to read response: %v\n", err)
					continue
				}
				if resp != nil {
					lastResp = append([]byte(nil), resp...)       // deep copy
					lastMutated = append([]byte(nil), mutated...) // deep copy
					lastIndex = idx
				}
			}

			// Log only if we got a response to some packet in the sequence.
			// Precursor(s) = everything sent BEFORE the final packet that got a response.
			if lastResp != nil && lastIndex >= 0 {
				precursors := [][]byte(nil)
				if lastIndex > 0 {
					precursors = make([][]byte, 0, lastIndex)
					for i := 0; i < lastIndex; i++ {
						precursors = append(precursors, sentSeq[i])
					}
				}
				localAddr := mutConn.LocalAddr().(*net.UDPAddr)
				logResult(item.Domain, item.MutationID, original, originalResponse, precursors, lastMutated, lastResp, localAddr.Port)
			}
		}
	}
}


func loadDomains(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	lines, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	var domains []string
	for _, line := range lines {
		if len(line) > 0 {
			domains = append(domains, line[0])
		}
	}
	return domains, nil
}

func loadMutations(filename string) (map[int]bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	lines, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	mutations := make(map[int]bool)
	for _, line := range lines {
		if len(line) < 2 {
			continue
		}
		id, err := strconv.Atoi(line[0])
		if err != nil {
			continue
		}
		enabled, err := strconv.ParseBool(line[1])
		if err != nil {
			continue
		}
		mutations[id] = enabled
	}
	return mutations, nil
}

func writef(format string, args ...any) {
	fmt.Fprintf(outputFile, format, args...)
	fmt.Printf(format, args...)
}
