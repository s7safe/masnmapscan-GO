package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type MasscanResult struct {
	IP    string `json:"ip"`
	Ports []struct {
		Port    int    `json:"port"`
		Proto   string `json:"proto"`
		Status  string `json:"status"`
		Reason  string `json:"reason"`
		TTL     int    `json:"ttl"`
		Service string `json:"service,omitempty"`
		Banner  string `json:"banner,omitempty"`
	} `json:"ports"`
}

type Scanner struct {
	ports     []string
	finalURLs map[string]bool
	ips       []string
	mutex     sync.Mutex
}

func NewScanner() *Scanner {
	return &Scanner{
		ports:     make([]string, 0),
		finalURLs: make(map[string]bool),
		ips:       make([]string, 0),
	}
}

func (s *Scanner) masportscan(scanIP string) error {
	// Run masscan
	cmd := exec.Command("./masscan", scanIP, "-p", "1-65535", "-oJ", "masscan.json", "--rate", "1000")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("masscan error: %v", err)
	}

	// Read and parse results
	data, err := ioutil.ReadFile("masscan.json")
	if err != nil {
		return fmt.Errorf("failed to read masscan.json: %v", err)
	}

	var tempPorts []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "{ ") {
			line = strings.TrimSuffix(line, ",")
			var result MasscanResult
			if err := json.Unmarshal([]byte(line), &result); err != nil {
				continue
			}
			for _, port := range result.Ports {
				tempPorts = append(tempPorts, fmt.Sprintf("%d", port.Port))
			}
		}
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(tempPorts) <= 50 {
		s.ports = append(s.ports, tempPorts...)
	}
	return nil
}

func (s *Scanner) nmapscan(scanIP string) error {
	for _, port := range s.ports {
		cmd := exec.Command("nmap", "-p", port, "-sV", scanIP)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("nmap scan error for %s:%s: %v", scanIP, port, err)
			continue
		}

		serviceName := s.parseNmapOutput(string(output))
		if strings.Contains(serviceName, "http") || serviceName == "sun-answerbook" {
			s.writeResult(fmt.Sprintf("%s:%s\n", scanIP, port))
		}
	}
	return nil
}

func (s *Scanner) parseNmapOutput(output string) string {
	if strings.Contains(output, "open") {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "open") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					return fields[2]
				}
			}
		}
	}
	return "unknown"
}

func (s *Scanner) writeResult(result string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	f, err := os.OpenFile("web_services.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening result file: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(result); err != nil {
		log.Printf("Error writing result: %v", err)
	}
}

func (s *Scanner) removeDuplicates() {
	if _, err := os.Stat("result.txt"); os.IsNotExist(err) {
		return
	}

	resultFile, err := os.Open("result.txt")
	if err != nil {
		log.Printf("Error opening result file: %v", err)
		return
	}
	defer resultFile.Close()

	finalResult, err := os.Create("final_result.txt")
	if err != nil {
		log.Printf("Error creating final result file: %v", err)
		return
	}
	defer finalResult.Close()

	urlFile, err := os.Create("url.txt")
	if err != nil {
		log.Printf("Error creating URL file: %v", err)
		return
	}
	defer urlFile.Close()

	scanner := bufio.NewScanner(resultFile)
	for scanner.Scan() {
		line := scanner.Text()
		if !s.finalURLs[line] {
			s.finalURLs[line] = true
			finalResult.WriteString(line + "\n")

			if strings.Contains(line, "Website") {
				url := strings.Split(strings.TrimPrefix(line, "[*] Website: "), "\t\t")[0]
				urlFile.WriteString(url + "\n")
			}
		}
	}

	os.Remove("result.txt")
}

func (s *Scanner) getDomainIP() error {
	subdomainFile, err := os.Open("subdomain.txt")
	if err != nil {
		return fmt.Errorf("error opening subdomain file: %v", err)
	}
	defer subdomainFile.Close()

	ipFile, err := os.Create("subdomain-ip.txt")
	if err != nil {
		return fmt.Errorf("error creating IP file: %v", err)
	}
	defer ipFile.Close()

	scanner := bufio.NewScanner(subdomainFile)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		lookupDomain := domain
		if strings.HasPrefix(domain, "www.") {
			lookupDomain = strings.TrimPrefix(domain, "www.")
		}

		ips, err := net.LookupIP(lookupDomain)
		if err != nil {
			log.Printf("Error looking up %s: %v", lookupDomain, err)
			continue
		}

		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				fmt.Printf("%s\t\t%s\n", domain, ipv4.String())
				ipFile.WriteString(fmt.Sprintf("%s\t\t%s\n", domain, ipv4.String()))
				s.ips = append(s.ips, ipv4.String())
			}
		}
	}

	// Remove duplicate IPs
	uniqueIPs := make(map[string]bool)
	finalIPFile, err := os.Create("ip.txt")
	if err != nil {
		return fmt.Errorf("error creating final IP file: %v", err)
	}
	defer finalIPFile.Close()

	for _, ip := range s.ips {
		if !uniqueIPs[ip] {
			uniqueIPs[ip] = true
			finalIPFile.WriteString(ip + "\n")
		}
	}

	return nil
}

func (s *Scanner) scanWorker(jobs <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for ip := range jobs {
		if err := s.masportscan(ip); err != nil {
			log.Printf("Error in masscan for %s: %v", ip, err)
			continue
		}
		if err := s.nmapscan(ip); err != nil {
			log.Printf("Error in nmap scan for %s: %v", ip, err)
		}
	}
}

func main() {
	startTime := time.Now()
	scanner := NewScanner()

	// Check if ip.txt exists
	if _, err := os.Stat("ip.txt"); os.IsNotExist(err) {
		if err := scanner.getDomainIP(); err != nil {
			log.Fatalf("Error getting domain IPs: %v", err)
		}
	}

	// Read IPs and start scanning
	ips, err := ioutil.ReadFile("ip.txt")
	if err != nil {
		log.Fatalf("Error reading IP file: %v", err)
	}

	jobs := make(chan string, 200)
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go scanner.scanWorker(jobs, &wg)
	}

	// Send jobs to workers
	for _, ip := range strings.Split(string(ips), "\n") {
		if ip = strings.TrimSpace(ip); ip != "" {
			jobs <- ip
		}
	}
	close(jobs)

	// Wait for all scans to complete
	wg.Wait()

	// Remove duplicates and cleanup
	scanner.removeDuplicates()

	fmt.Printf("Program completed in %v seconds\n", time.Since(startTime).Seconds())
}
