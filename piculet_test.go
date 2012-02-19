package main

import (
	"testing"
)

var guessTests = [][4]string{
	{"md5", "", "acbd18db4cc2f85cedef654fccc4a4d8", "foo"},
	{"md5", "abc", "738af958f3a30c05e9725dbf4adab60a", "f0o"},
}

func TestPiculet(t *testing.T) {
	sem := make(chan bool, 4)
	for i, v := range guessTests {
		ch := make(chan string)
		g := Guesser{
			Alg:    v[0],
			Salt:   v[1],
			Digest: v[2],
			Max:    len(v[3]),
			Result: ch,
			sem:    sem,
		}
		go g.Run()
		res := <-g.Result
		if res != v[3] {
			saltStr := g.Salt
			if saltStr == "" {
				saltStr = "<none>"
			}
			t.Errorf("Error in test %d: Got %s instead of %s (salt:digest %s:%s)", i+1, res, v[3], saltStr, g.Digest)
		}
	}
}
