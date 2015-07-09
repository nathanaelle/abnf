package abnf

import (
	"testing"
)

func Test_ABNF_SPF(t *testing.T) {
	sorted_ABNF_SPF := normalize(ABNF_SPF)

	valid_ABNF,target := ABNF().Valid([ ]byte(sorted_ABNF_SPF))
	if !valid_ABNF {
		t.Errorf("errors found in \n---------\n%s\n---------\n", sorted_ABNF_SPF)
	}

	spf :=	ABNF().Compile(target,"record")

	tested_ABNF := spf.String()
	if tested_ABNF != sorted_ABNF_SPF {
		t.Errorf("difference between \n---------\n%s\n---------\nand\n---------\n%s\n---------\n ", sorted_ABNF_SPF, tested_ABNF)
	}


	log_test := log_if_invalid(t)

	log_test(spf.Valid([]byte("v=spf1")))
	log_test(spf.Valid([]byte("v=spf1 +all")))
	log_test(spf.Valid([]byte("v=spf1 a -all")))

	Verbose = true
	log_test(spf.Valid([]byte("v=spf1 mx/30 mx:example.org/30 -all")))
	Verbose = false

}


func log_if_invalid(t *testing.T) func(bool,Target){
	return func(valid bool, tree Target)  {
		if !valid {
			t.Errorf("valid SPF is not valid !")
			for _,c := range tree.Childs {
				t.Errorf("[%s]\n", c.String())
			}
			t.Errorf("--[%s]--\n", string(tree.Value))
		}
	}
}



var ABNF_SPF string = `record = Version Terms *sp
version = "v=spf1"
terms = *(1*sp (Directive / Modifier))
directive = [ qualifier ] Mechanism
qualifier = "+" / "-" / "?" / "~"
mechanism = (Include / A / All / MX / PTR / IP4 / IP6 / Exists)
all = "all"
include = "include" ":" Domain-spec
A = "a" [ ":" Domain-spec ] [ dual-cidr-length ]
MX = "mx" [ ":" Domain-spec ] [ dual-cidr-length ]
PTR = "ptr" [ ":" Domain-spec ]
IP4 = "ip4" ":" Ip4-network [ ip4-cidr-length ]
IP6 = "ip6" ":" Ip6-network [ ip6-cidr-length ]
exists = "exists" ":" Domain-spec
modifier = Redirect / Explanation / unknown-modifier
redirect = "redirect" "=" Domain-spec
explanation = "exp" "=" Domain-spec
unknown-modifier = name "=" macro-string
ip4-cidr-length = "/" 1*digit
ip6-cidr-length = "/" 1*digit
dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]
ip4-network = qnum "." qnum "." qnum "." qnum
qnum = digit / %x31-39 digit / "1" 2digit / "2" %x30-34 digit / "25" %x30-35
ip6-network = 6(h16 ":") ls32 / "::" 5(h16 ":") ls32 / [ h16 ] "::" 4(h16 ":") ls32 / [ *1(h16 ":") h16 ] "::" 3(h16 ":") ls32 / [ *2(h16 ":") h16 ] "::" 2(h16 ":") ls32 / [ *3(h16 ":") h16 ] "::" h16 ":" ls32 / [ *4(h16 ":") h16 ] "::" ls32 / [ *5(h16 ":") h16 ] "::" h16 / [ *6(h16 ":") h16 ] "::"
h16 = 1*4hexdig
ls32 = (h16 ":" h16) / ip4-network
domain-spec = macro-string domain-end
domain-end = ("." toplabel [ "." ]) / macro-expand
toplabel = (*alphanum alpha *alphanum) / (1*alphanum "-" *(alphanum / "-") alphanum)
alphanum = alpha / digit
explain-string = *(macro-string / sp)
macro-string = *(macro-expand / macro-literal)
macro-expand = ("%{" macro-letter transformers *delimiter "}") / "%%" / "%_" / "%-"
macro-literal = %x21-24 / %x26-7E
macro-letter = "s" / "l" / "o" / "d" / "i" / "p" / "h" / "c" / "r" / "t"
transformers = *digit [ "r" ]
delimiter = "." / "-" / "+" / "," / "/" / "_" / "="
name = alpha *(alpha / digit / "-" / "_" / ".")
header-field = "Received-SPF:" [ cfws ] result fws [ comment fws ] [ key-value-list ] crlf
result = "Pass" / "Fail" / "SoftFail" / "Neutral" / "None" / "TempError" / "PermError"
key-value-list = key-value-pair *(";" [ cfws ] key-value-pair) [ ";" ]
key-value-pair = key [ cfws ] "=" (dot-atom / quoted-string)
key = "client-ip" / "envelope-from" / "helo" / "problem" / "receiver" / "identity" / mechanism / "x-" name / name
identity = "mailfrom" / "helo" / name
alpha = %x41-5A / %x61-7A
digit = %x30-39
lf = %x0A
cr = %x0D
crlf = cr lf
sp = %x20 / %x09
hexdig = digit / "A" / "B" / "C" / "D" / "E" / "F"
fws = ([ *sp crlf ] 1*sp) / obs-fws
obs-fws = 1*sp *(crlf 1*sp)
ctext = no-ws-ctl / %x21-27 / %x2A-5B / %x5D-7E
ccontent = ctext / quoted-pair / comment
comment = "(" *([ fws ] ccontent) [ fws ] ")"
cfws = *([ fws ] comment) (([ fws ] comment) / fws)
quoted-pair = ("\" text) / obs-qp
obs-qp = "\" (%x00-7F)
no-ws-ctl = %x01-08 / %x0B / %x0C / %x0E-1F / %x7F
quoted-string = [ cfws ] DQUOTE *([ fws ] qcontent) [ fws ] DQUOTE [ cfws ]
qtext = no-ws-ctl / %x21 / %x23-5B / %x5D-7E
qcontent = qtext / quoted-pair
dot-atom = [ cfws ] dot-atom-text [ cfws ]
dot-atom-text = 1*atext *("." 1*atext)
atext = alpha / digit / "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "/" / "=" / "?" / "^" / "_" / %x60 / "{" / "|" / "}" / "~"`
