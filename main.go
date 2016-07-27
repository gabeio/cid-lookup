package main

/*

this binary parses jcblock callerId.dat to callerId.csv

*/

import (
	"log"
	"fmt"
	"os"
	"bufio"
	"regexp"
	"time"
	"strconv"

	"github.com/fsnotify/fsnotify"
	"github.com/parnurzeal/gorequest"
)

var (
	done chan bool
	br *bufio.Reader
	bw *bufio.Writer
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func get(req *gorequest.SuperAgent, url string, referer string, ua string) (body string) {
	req.Timeout(time.Second * 7)
	req.Get(url)
	if len(referer) > 0 {
		req.Set("Referer", referer)
	}
	resp, body, err := req.Set("User-Agent", ua).
		Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8").
		// Set("Accept-Encoding", "gzip, deflate, sdch").
		Set("Accept-Language", "en-US,en;q=0.8").
		Set("Dnt", "1").
		Set("Origin", "http://www.neopets.com").
		Set("Pragma", "no-cache").
		Set("Cache-Control", "no-cache").
		// SetDebug(false).
		End()
	time.Sleep(time.Second*7)
	if err != nil {
		log.Printf("> ERROR(get): %s :: %s\n", url, err)
		log.Println(err)
		return
	}
	if resp.StatusCode != 200 {
		log.Printf("Status Code: %d\n", resp.StatusCode)
	}
	return body
}

func post(req *gorequest.SuperAgent, url string, referer string, ua string, data string) {
	req.Timeout(time.Second * 7)
	req.Post(url)
	if len(referer) > 0 {
		req.Set("Referer", referer)
	}
	resp, _, err := req.Type("form").
		Set("User-Agent", ua).
		Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8").
		// Set("Accept-Encoding", "gzip, deflate, sdch").
		Set("Accept-Language", "en-US,en;q=0.8").
		Set("Dnt", "1").
		Set("Pragma", "no-cache").
		Set("Cache-Control", "no-cache").
		Send(data).
		// SetDebug(true).
		End()
	time.Sleep(time.Second*7)
	if err != nil {
		log.Printf("> ERROR(post): %s :: %s\n", url, err)
		return
	}
	if resp.StatusCode != 200 {
		log.Printf("Status Code: %d\n", resp.StatusCode)
	}
}

func secondtolastLine(b *bufio.Reader) string {
	var err error
	var line string
	var line2 string
	for {
		line2 = line
		line, err = b.ReadString('\n')
		if err != nil {
			log.Println(err)
			break;
		}
	}
	return line2
}

func isItSpam(number string) bool {
	spamRe := regexp.MustCompile("<span class='pull-right'>\n([0-9]{1,3})%\n</span>")
	req := gorequest.New()
	url := fmt.Sprintf("http://mrnumber.com/1-%s-%s-%s", number[0:3], number[3:6], number[6:10])
	body := get(req, url, "", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.21 Safari/537.36")
	res := spamRe.FindAllStringSubmatch(string(body), -1)
	if len(res[0]) > 0 {
		// good
		i, err := strconv.Atoi(res[0][1])
		check(err)
		if i >= 50 {
			// it's spam!
			log.Println("it's spam!1!")
			return true
		} else {
			log.Println("it's probably not spam")
			return false
		}
	} else {
		log.Println("we might be blocked by captcha")
		return false // unknown
	}
	log.Println("unknown")
	return false
}

func parse() {
	// open readonly dat file
	fd, err := os.OpenFile("/home/pi/jcblock/callerID.dat", os.O_RDONLY, 0444)
	check(err)
	defer fd.Close()
	// create "read" buffer Reader
	br = bufio.NewReader(fd)
	// err := os.Remove("/home/pi/jcblock/callerID.csv")
	cid := regexp.MustCompile("^([-BW])-DATE = ([0-9]{6})--TIME = ([0-9]{4})--NAME = (.{1,15})--NMBR = ([0-9OP]{1,})--")
	// comma := regexp.MustCompile(",")
	// for {
	line := secondtolastLine(br)//br.ReadBytes('\n')
	// if err == nil {
	// we have a line
	log.Printf("line: %s\n", line)
	ssm := cid.FindAllStringSubmatch(string(line), -1) // find caller id parts from jcblock
	log.Printf("ssm: %v\n", ssm)
	if len(ssm) == 1 && len(ssm[0]) > 1 {
		if ssm[0][1] == "-" { // undecided number
			// check number
			spam := isItSpam(ssm[0][5])
			if spam {
				wline := fmt.Sprintf("%s?        ++++++        Spam\n", string(ssm[0][5]))
				l, err := bw.WriteString(wline)
				if len(wline) != l {
					log.Println("write & string lengths do not match!")
				}
				check(err)
				bw.Flush()
			}
		}
	} else {
		log.Printf("len(ssm): %d\n", len(ssm))
	}
	// }
	// else io.EOF for loop will break and function will complete
	// }
}

func watch(watcher *fsnotify.Watcher) {
	for {
		log.Println("for loop")
		select {
		case event := <-watcher.Events:
			log.Println("event:", event)
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Println("modified file:", event.Name)
				parse()
			}
		case err := <-watcher.Errors:
			log.Println("error:", err)
		}
	}
}

func main() {
	log.Println("cid-lookup started")
	defer log.Println("cid-lookup ended")
	// open blacklist for appending
	f, err := os.OpenFile("/home/pi/jcblock/blacklist.dat", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	check(err)
	defer f.Close()
	// create "write" buffer Writer
	bw = bufio.NewWriter(f)
	check(err)

	// now watch file for changes
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()
	done = make(chan bool)
	go watch(watcher)

	err = watcher.Add("/home/pi/jcblock/callerID.dat")
	if err != nil {
		log.Fatal(err)
	}
	<-done
}
