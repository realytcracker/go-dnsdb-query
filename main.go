/*

go-dnsdb-query by ytcracker
go wrapper for farsight security's dnsdb.info api
requires a valid api key to function in the junction
this program is NOT analogous to the dnsdb query python script
it has its own ideas about existence

*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

//Config is loaded from config.json
type Config struct {
	DNSDBAPIKey string `json:"dnsDBAPIKey"`
	DNSDBURL    string `json:"dnsDBAPIURL"`
}

//DNSRecord holds the DNS like a PNS
type DNSRecord []struct {
	Count     int      `json:"count"`
	TimeFirst int      `json:"time_first"`
	RRType    string   `json:"rrtype"`
	RRName    string   `json:"rrname"`
	Bailiwick string   `json:"bailiwick"`
	RData     []string `json:"rdata"`
	TimeLast  int      `json:"time_last"`
}

func main() {
	var config Config
	var dnsRecord DNSRecord
	var raw, deduped []string

	flagDaysBack := flag.Int("t", 14, "historical number of days to search")
	flagDomain := flag.String("d", "(*.)example.com", "target domain name/wildcard")
	flag.Parse()
	domain := url.QueryEscape(*flagDomain)

	//get epoch time
	now := time.Now()
	secs := now.Unix() - int64(*flagDaysBack*24*3600)

	if domain == "%28%2A.%29example.com" {
		fmt.Println("           _       ")
		fmt.Println("  __ _  __| | __ _ ")
		fmt.Println(" / _` |/ _` |/ _` |")
		fmt.Println("| (_| | (_| | (_| | go-dnsdb-query by ytcracker")
		fmt.Println(" \\__, |\\__,_|\\__, |")
		fmt.Println(" |___/          |_|")
		fmt.Printf("\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println("")
		return
	}

	file, err := os.Open("config.json")
	if err != nil {
		fmt.Println("error loading config.json.")
		return
	}
	json.NewDecoder(file).Decode(&config)

	//proxy settings and shit could go here eventually
	tr := &http.Transport{}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", config.DNSDBURL+"/lookup/rrset/name/"+domain+"/a/?limit=999999&time_last_after="+strconv.FormatInt(secs, 10), nil)
	req.Header.Add("X-API-Key", config.DNSDBAPIKey)
	req.Header.Add("Accept", "application/json")

	//fmt.Println("fetching " + config.DNSDBURL + "/lookup/rrset/name/" + domain + "/a/?limit=999999&time_last_after=" + strconv.FormatInt(secs, 10) + "...")

	response, _ := client.Do(req)
	body, _ := ioutil.ReadAll(response.Body)
	response.Body.Close()

	//the json you get from DNSDB is bad, so format it correctly
	//fmt.Println("reformatting json...")

	validjson := "[" + strings.Replace(string(body), "}", "},", -1)
	validjson = validjson[:len(validjson)-2] + "]"

	//fmt.Println("decoding json...")
	_ = json.NewDecoder(strings.NewReader(validjson)).Decode(&dnsRecord)

	for _, record := range dnsRecord {
		//remove period at the end
		raw = append(raw, record.RRName[:len(record.RRName)-1])
	}
	//fmt.Println("removing duplicates...")
	deduped = removeDuplicates(raw)

	for _, record := range deduped {
		//remove period at the end
		fmt.Println(record)
	}
}

func removeDuplicates(elements []string) []string {
	encountered := map[string]bool{}

	// Create a map of all unique elements.
	for v := range elements {
		encountered[elements[v]] = true
	}

	// Place all keys from the map into a slice.
	result := []string{}
	for key := range encountered {
		result = append(result, key)
	}
	return result
}
