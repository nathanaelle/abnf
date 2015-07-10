package abnf

import (
	"testing"
	"sort"
	"strings"
)




func Test_ABNF_String(t *testing.T) {
	sorted_ABNF_ABNF:= normalize(strings.ToUpper(ABNF_ABNF_7405))
	sorted_ABNF	:= normalize(strings.ToUpper(ABNF().String()))

	if sorted_ABNF != sorted_ABNF_ABNF {
		t.Errorf("difference between \n---------\n%s\n---------\nand\n---------\n%s\n---------\n ", sorted_ABNF_ABNF, sorted_ABNF )
	}
}

func Test_ABNF_ABNF_5234(t *testing.T) {
	sorted_ABNF_ABNF:= []byte(normalize(ABNF_ABNF_5234))
	tested_ABNF,_	:= ABNF().Valid(sorted_ABNF_ABNF)

	if !tested_ABNF {
		t.Errorf("errors found in \n---------\n%s\n---------\n", ABNF_ABNF_5234)
	}
}

func Test_ABNF_ABNF_7405(t *testing.T) {
	sorted_ABNF_ABNF:= []byte(normalize(ABNF_ABNF_7405))
	tested_ABNF,_	:= ABNF().Valid(sorted_ABNF_ABNF)

	if !tested_ABNF {
			t.Errorf("errors found in \n---------\n%s\n---------\n", ABNF_ABNF_7405)
	}
}





func Benchmark_ABNF_call(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ABNF()
	}
}

func Benchmark_ABNF_String(b *testing.B) {
	abnf := ABNF()

	for i := 0; i < b.N; i++ {
		abnf.String()
	}
}


func Benchmark_ABNF_Valid(b *testing.B) {
	sorted_ABNF_ABNF := normalize(ABNF_ABNF_5234)
	abnf := ABNF()

	for i := 0; i < b.N; i++ {
		abnf.Valid([]byte(sorted_ABNF_ABNF))
	}
}






func normalize(d string) string {
	ret := strings.Split(d,"\n")
	for i,_ := range ret {
		ret[i] = strings.Trim(ret[i],"\r\n")
	}
	sort.Strings(ret)
	return strings.Trim(strings.Join(ret,"\r\n"),"\r\n") + "\r\n"
}



// RFC 5234 errata 2968 3076 applied
// char-val is a quoted-string as in 7405
var ABNF_ABNF_5234 string = `rulelist = 1*(rule / (*WSP c-nl))
rule = rulename defined-as elements c-nl
rulename = ALPHA *(ALPHA / DIGIT / "-")
defined-as = *c-wsp ("=" / "=/") *c-wsp
elements = alternation *WSP
c-wsp = WSP / (c-nl WSP)
c-nl = comment / CRLF
comment = ";" *(WSP / VCHAR) CRLF
alternation = concatenation *(*c-wsp "/" *c-wsp concatenation)
concatenation = repetition *(1*c-wsp repetition)
repetition = [ repeat ] element
repeat = 1*DIGIT / (*DIGIT "*" *DIGIT)
element = rulename / group / option / char-val / num-val / prose-val
group = "(" *c-wsp alternation *c-wsp ")"
option = "[" *c-wsp alternation *c-wsp "]"
char-val = quoted-string
quoted-string = DQUOTE *(%x20-21 / %x23-7E) DQUOTE
num-val = "%" (bin-val / dec-val / hex-val)
bin-val = "b" 1*BIT [ 1*("." 1*BIT) / ("-" 1*BIT) ]
dec-val = "d" 1*DIGIT [ 1*("." 1*DIGIT) / ("-" 1*DIGIT) ]
hex-val = "x" 1*HEXDIG [ 1*("." 1*HEXDIG) / ("-" 1*HEXDIG) ]
prose-val = "<" *(%x20-3D / %x3F-7E) ">"
ALPHA = %x41-5A / %x61-7A
BIT = "0" / "1"
CHAR = %x01-7F
CR = %x0D
CRLF = CR LF
CTL = %x00-1F / %x7F
DIGIT = %x30-39
DQUOTE = %x22
HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
HTAB = %x09
LF = %x0A
LWSP = *(WSP / CRLF WSP)
OCTET = %x00-FF
SP = %x20
VCHAR = %x21-7E
WSP = SP / HTAB`

var ABNF_ABNF_7405 string = `rulelist = 1*(rule / (*WSP c-nl))
rule = rulename defined-as elements c-nl
rulename = ALPHA *(ALPHA / DIGIT / "-")
defined-as = *c-wsp ("=" / "=/") *c-wsp
elements = alternation *WSP
c-wsp = WSP / (c-nl WSP)
c-nl = comment / CRLF
comment = ";" *(WSP / VCHAR) CRLF
alternation = concatenation *(*c-wsp "/" *c-wsp concatenation)
concatenation = repetition *(1*c-wsp repetition)
repetition = [ repeat ] element
repeat = 1*DIGIT / (*DIGIT "*" *DIGIT)
element = rulename / group / option / char-val / num-val / prose-val
group = "(" *c-wsp alternation *c-wsp ")"
option = "[" *c-wsp alternation *c-wsp "]"
char-val = case-insensitive-string / case-sensitive-string
case-insensitive-string = [ "%i" ] quoted-string
case-sensitive-string = "%s" quoted-string
quoted-string = DQUOTE *(%x20-21 / %x23-7E) DQUOTE
num-val = "%" (bin-val / dec-val / hex-val)
bin-val = "b" 1*BIT [ 1*("." 1*BIT) / ("-" 1*BIT) ]
dec-val = "d" 1*DIGIT [ 1*("." 1*DIGIT) / ("-" 1*DIGIT) ]
hex-val = "x" 1*HEXDIG [ 1*("." 1*HEXDIG) / ("-" 1*HEXDIG) ]
prose-val = "<" *(%x20-3D / %x3F-7E) ">"
ALPHA = %x41-5A / %x61-7A
BIT = "0" / "1"
CHAR = %x01-7F
CR = %x0D
CRLF = CR LF
CTL = %x00-1F / %x7F
DIGIT = %x30-39
DQUOTE = %x22
HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
HTAB = %x09
LF = %x0A
LWSP = *(WSP / CRLF WSP)
OCTET = %x00-FF
SP = %x20
VCHAR = %x21-7E
WSP = SP / HTAB`
