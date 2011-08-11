package main

import (
	"crypto/md4"
	"crypto/md5"
	"crypto/ripemd160"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	"hash"
	"log"
	"time"
)

const (
	version string = "0.1"
)

var (
	sem        chan bool
	useSalt    bool = false
	gHash      string
	characters         = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ")
	alg        *string = flag.String("a", "md5", "hash algorithm")
	throttle   *int    = flag.Int("c", 1, "concurrency level")
	minLen     *int    = flag.Int("min", 1, "minimum password length")
	maxLen     *int    = flag.Int("max", 10, "maximum password length")
	gSalt      *string = flag.String("s", "", "salt")
)

func recurseOne(gen hash.Hash, width, pos int, g []byte, ch chan<- string) {
	var gh string
	for _, v := range characters {
		if pos < width-1 {
			recurseOne(gen, width, pos+1, g, ch)
		}
		g[pos] = v
		if useSalt {
			gen.Write([]byte(*gSalt))
		}
		gen.Write(g)
		gh = fmt.Sprintf("%x", gen.Sum())
		//fmt.Println("salt:", s, "hash:", h, "gh:", gh, "str:", string(g))
		if gh == gHash {
			ch <- string(g)
			return
		}
		gen.Reset()
	}
}

func GuessHash(alg string, ch chan<- string) {
	for i := 1; i < *maxLen; i++ {
		sem <- true
		go func() {
			var gen hash.Hash
			switch alg {
			default:
				log.Fatalln("Invalid algorithm")
			case "md4":
				gen = md4.New()
			case "md5":
				gen = md5.New()
			case "ripemd160":
				gen = ripemd160.New()
			case "sha1":
				gen = sha1.New()
			case "sha224":
				gen = sha256.New224()
			case "sha256":
				gen = sha256.New()
			case "sha384":
				gen = sha512.New384()
			case "sha512":
				gen = sha512.New()
			}
			recurseOne(gen, i, 0, make([]byte, *maxLen), ch)
			<-sem
		}()
	}
}

func main() {
	var start, finish int64
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		return
	}
	if *gSalt != "" {
		useSalt = true
	}
	gHash = flag.Arg(0)
	ch := make(chan string)
	sem = make(chan bool, *throttle)
	start = time.Nanoseconds()
	go GuessHash(*alg, ch)
	res := <-ch
	finish = time.Nanoseconds()
	log.Println("Value:", res)
	log.Println("Time taken:", (finish-start)/1e9, "seconds")
}
