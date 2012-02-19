package main

import (
	"code.google.com/p/go.crypto/md4"
	"code.google.com/p/go.crypto/ripemd160"
	"crypto/md5"
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
	version = "0.1"
)

var (
	characters         = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ")
	alg        *string = flag.String("a", "md5", "hash algorithm")
	throttle   *int    = flag.Int("c", 4, "concurrency level")
	minLen     *int    = flag.Int("min", 1, "minimum password length")
	maxLen     *int    = flag.Int("max", 10, "maximum password length")
	gSalt      *string = flag.String("s", "", "salt")
)

type Guesser struct {
	Alg    string
	Salt   string
	Digest string
	Min    int
	Max    int
	Result chan string
	salt   []byte
	sem    chan bool
}

func (g *Guesser) guess(h hash.Hash, width, pos int, b []byte) {
	for _, v := range characters {
		if pos < width-1 {
			g.guess(h, width, pos+1, b)
		}
		b[pos] = v
		if g.salt != nil {
			h.Write(g.salt)
		}
		h.Write(b)
		// Do []byte comparison instead
		d := fmt.Sprintf("%x", h.Sum(nil))
		// fmt.Println("Guessed", d, "against", g.Digest)
		if d == g.Digest {
			g.Result <- string(b)
			return
		}
		h.Reset()
	}
}

func (g *Guesser) Run() {
	if g.Salt != "" {
		g.salt = []byte(g.Salt)
	}
	for i := g.Min; i < g.Max; i++ {
		g.sem <- true
		h, err := GetHash(g.Alg)
		if err != nil {
			panic(err)
		}
		go func() {
			g.guess(h, i, 0, make([]byte, g.Max))
			<-g.sem
		}()
	}
}

func GetHash(alg string) (hash.Hash, error) {
	var h hash.Hash
	switch alg {
	default:
		return nil, fmt.Errorf("Invalid algorithm")
	case "md4":
		h = md4.New()
	case "md5":
		h = md5.New()
	case "ripemd160":
		h = ripemd160.New()
	case "sha1":
		h = sha1.New()
	case "sha224":
		h = sha256.New224()
	case "sha256":
		h = sha256.New()
	case "sha384":
		h = sha512.New384()
	case "sha512":
		h = sha512.New()
	}
	return h, nil
}

// init is called before main
func init() {
	flag.Parse()
}

func main() {
	if flag.NArg() == 0 {
		flag.Usage()
		return
	}
	ch := make(chan string)
	sem := make(chan bool, *throttle)
	g := Guesser{
		Alg:    *alg,
		Salt:   *gSalt,
		Digest: flag.Arg(0),
		Min:    *minLen,
		Max:    *maxLen,
		Result: ch,
		sem:    sem,
	}
	start := time.Now()
	go g.Run()
	res := <-g.Result
	log.Println("Value:", res)
	log.Println("Time taken:", time.Since(start))
}
