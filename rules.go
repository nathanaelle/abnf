package abnf	// import "github.com/nathanaelle/abnf"
import	(
	"strings"
	"fmt"
)

type(
	extent		struct {
		start,end	byte
	}


	Expression	interface {
		ABNF()		string
		Match([]byte)	(bool,[]Target,[]byte)
	}

	ABNF_Concat	struct {
		abnf	string
		exprs	[]Expression
	}

	ABNF_Altern	struct {
		abnf	string
		exprs	[]Expression
	}

	ABNF_Group	struct {
		abnf	string
		exprs	[]Expression
	}

	ABNF_Option	struct {
		abnf	string
		expr	Expression
	}

	ABNF_Range	struct {
		abnf	string
		extents	[]extent
	}

	ABNF_Star	struct {
		min,max	int
		abnf	string
		expr	Expression
	}

	ABNF_Assign	struct {
		abnf	string
		expr	Expression
	}

	ABNF_Ref	struct {
		abnf	string
		get	func()Expression
	}

	ABNF_Single_ci	struct {
		abnf	string
		tokens	[]byte
	}

	ABNF_Single_cs	struct {
		abnf	string
		tokens	[]byte
	}

	ABNF_Single_byte	struct {
		abnf	string
		tokens	[]byte
	}
)


func abnf_single_byte(tokens []byte) string {
	ret := make([]string, 0, len(tokens))

	for _,tok := range tokens {
		ret = append( ret, fmt.Sprintf("%%x%02X",tok) )
	}

	return strings.Join(ret," ")
}




func abnfs(exprs []Expression) []string {
	ret := make([]string,len(exprs))
	for i,expr := range exprs {
		ret[i] = expr.ABNF()
	}
	return ret
}


func abnf_star(min ,max int,b string) string {
	switch {
		case min == 0 && max == 0:	return fmt.Sprintf("*%s",b)
		case min == max:		return fmt.Sprintf("%d%s",min,b)
		case min == 0:			return fmt.Sprintf("*%d%s",max,b)
		case max == 0:			return fmt.Sprintf("%d*%s",min,b)
		default:			return fmt.Sprintf("%d*%d%s",min,max,b)
	}
}




func concat(exprs ...Expression) Expression {
	/*if len(exprs) == 1 {
		return exprs[0]
	}*/

	return &ABNF_Concat {
		abnf:	strings.Join( abnfs(exprs)," "),
		exprs:	exprs,
	}
}

func	(abnf *ABNF_Concat)ABNF()	string {
	return abnf.abnf
}

func	(abnf *ABNF_Concat)Match(buffer []byte)	(bool,[]Target,[]byte) {
	end	:= buffer
	resp	:= []Target{}
	for _,exp := range abnf.exprs {
		var ok		bool
		var t_resp	[]Target

		ok,t_resp,end = exp.Match(end);
		if  !ok {
			return	false, []Target{ }, buffer
		}
		resp = append(resp, t_resp...)
	}
	return true,resp,end
}





func choice(exprs ...Expression) Expression {
	/*if len(exprs) == 1 {
		return exprs[0]
	}*/

	return &ABNF_Altern {
		abnf:	strings.Join( abnfs(exprs)," / "),
		exprs:	exprs,
	}
}

func	(abnf *ABNF_Altern)ABNF()	string {
	return abnf.abnf
}

func	(abnf *ABNF_Altern)Match(buffer []byte)	(bool,[]Target,[]byte) {
	// " / " works right to left … not left to right like the rest
	for i:=len(abnf.exprs)-1; i>=0 ; i-- {
		if ok, buff,end := abnf.exprs[i].Match(buffer); ok {
			return ok, buff, end
		}
	}

	return	false, []Target{ }, buffer
}





func group(exprs ...Expression) Expression {
	return &ABNF_Group {
		abnf:	"(" + strings.Join( abnfs(exprs)," ") + ")",
		exprs:	exprs,
	}
}

func	(abnf *ABNF_Group)ABNF()	string {
	return abnf.abnf
}

func	(abnf *ABNF_Group)Match(buffer []byte)	(bool,[]Target,[]byte) {
	end	:= buffer
	resp	:= []Target{}

	for _,exp := range abnf.exprs {
		var ok		bool
		var t_resp	[]Target

		ok,t_resp,end = exp.Match(end);
		if  !ok {
			return	false, []Target{ }, buffer
		}
		resp = append(resp, t_resp...)
	}
	return true,resp,end
}





func option(expr Expression) Expression {
	return &ABNF_Option {
		abnf:	"[ "+ expr.ABNF() +" ]",
		expr:	expr,
	}
}

func	(abnf *ABNF_Option)ABNF()	string {
	return abnf.abnf
}

func	(abnf *ABNF_Option)Match(buffer []byte)	(bool,[]Target,[]byte) {
	ok,resp,end := abnf.expr.Match(buffer);

	if  !ok {
		return true, []Target{}, buffer
	}

	return true, resp, end
}







func	extents(start,end byte) Expression {
	return &ABNF_Range {
		abnf:	fmt.Sprintf("%%x%02X-%02X",start, end),
		extents: []extent{ {start,end} },
	}
}

func	(abnf *ABNF_Range)ABNF()	string {
	return abnf.abnf
}

func	(abnf *ABNF_Range)Match(buffer []byte)	(bool,[]Target,[]byte) {
	for _,extent := range abnf.extents {
		if buffer[0] >= extent.start && buffer[0] <= extent.end {
			return	true, []Target{ { Value: buffer[0:1] } }, buffer[1:]
		}
	}

	return	false, []Target{ }, buffer
}







func star(min ,max int, expr Expression) Expression {
	if min == max && min == 1 {
		return expr
	}

	return &ABNF_Star {
		abnf:	abnf_star(min,max, expr.ABNF()),
		min:	min,
		max:	max,
		expr:	expr,
	}
}


func	(abnf *ABNF_Star)ABNF()	string {
	return abnf.abnf
}

func	(abnf *ABNF_Star)Match(buffer []byte)	(bool,[]Target,[]byte) {
	idx	:= 0
	end	:= buffer
	resp	:= []Target{}

	for {
		ok,t_resp,t_end := abnf.expr.Match(end);
		if  !ok {
			break
		}
		idx++
		resp	= append(resp, t_resp...)
		end	= t_end

		if idx == abnf.max {
			break
		}

		if len(end) == 0 {
			break
		}
	}

	if idx < abnf.min {
		return	false, []Target{ }, buffer
	}

	return true, resp, end
}



func	(abnf *ABNF_Assign)ABNF()	string {
	return abnf.abnf
}

func	(abnf *ABNF_Assign)Match(buffer []byte)	(bool,[]Target,[]byte) {
	return abnf.expr.Match(buffer)
}



func	(abnf *ABNF_Ref)ABNF()	string {
	return abnf.abnf
}

func	(abnf *ABNF_Ref)Match(buffer []byte)	(bool,[]Target,[]byte) {
	if Verbose {
		fmt.Printf("Ref\t\t-> [%s]\n", string(abnf.abnf) )
	}


	t,targets,end := abnf.get().Match(buffer)
	if Verbose {
		fmt.Printf("Ref\t%t\t<- [%s]\n", t, string(abnf.abnf) )
		fmt.Printf("Ref\t\t<- [%s]\n", string(end) )
		for _,t := range targets {
			fmt.Printf("\t\t<- [%s]\n", t.String() )
		}
	}
	return t, []Target{ { Rule: abnf.abnf, Childs:targets } }, end
}










func	single_ci(single ...byte) Expression {
	return &ABNF_Single_ci {
		abnf: fmt.Sprintf("\"%s\"",string(single)),
		tokens: single,
	}
}

func	mutator_ci(expr Expression) Expression {
	switch expr.(type) {
		case *ABNF_Single_ci:
			return expr

		case *ABNF_Single_cs:
			tokens := expr.(*ABNF_Single_cs).tokens
			return &ABNF_Single_ci {
				abnf: fmt.Sprintf("\"%s\"",string(tokens)),
				tokens: tokens,
			}

		case *ABNF_Single_byte:
			tokens := expr.(*ABNF_Single_byte).tokens
			return &ABNF_Single_ci {
				abnf: fmt.Sprintf("\"%s\"",string(tokens)),
				tokens: tokens,
			}
	}
	panic("WTF !"+expr.ABNF())
}



func	(abnf *ABNF_Single_ci)ABNF()	string {
	return abnf.abnf
}

func	(abnf *ABNF_Single_ci)Match(buffer []byte)	(bool,[]Target,[]byte) {
	if Verbose {
		fmt.Printf("single_ci\t-> %d | %d\n", len(abnf.tokens), len(buffer) )
		fmt.Printf("\t\t-> [%s]\n", string(abnf.abnf) )
		fmt.Printf("\t\t-> [%s]\n", string(buffer) )
	}

	if len(abnf.tokens) > len(buffer) {
		return false, []Target{ }, buffer
	}

	for i,tok := range abnf.tokens {
		switch {
			case (tok >= 'a' && tok <= 'z') || (tok >= 'A' && tok <= 'Z'):
				if (tok|0x20) != (buffer[i]|0x20) {
					return	false, []Target{ }, buffer
				}

			default:
				if tok != buffer[i] {
					return	false, []Target{ }, buffer
				}
		}
	}

	if Verbose {
		fmt.Printf("\t\t-> [%s]\n", buffer[0:len(abnf.tokens)] )
	}

	return	true, []Target{ { Value: buffer[0:len(abnf.tokens)] } }, buffer[len(abnf.tokens):]
}





func	single_cs(single ...byte) Expression {
	return &ABNF_Single_cs {
		abnf: fmt.Sprintf("%%s\"%s\"",string(single)),
		tokens: single,
	}
}

func	mutator_cs(expr Expression) Expression {
	switch expr.(type) {
		case *ABNF_Single_cs:
			return expr

		case *ABNF_Single_ci:
			tokens := expr.(*ABNF_Single_ci).tokens
			return &ABNF_Single_cs {
				abnf: fmt.Sprintf("%%s\"%s\"",string(tokens)),
				tokens: tokens,
			}

		case *ABNF_Single_byte:
			tokens := expr.(*ABNF_Single_byte).tokens
			return &ABNF_Single_cs {
				abnf: fmt.Sprintf("%%s\"%s\"",string(tokens)),
				tokens: tokens,
			}
	}
	panic("WTF !"+expr.ABNF())
}




func	(abnf *ABNF_Single_cs)ABNF()	string {
	return abnf.abnf
}

func	(abnf *ABNF_Single_cs)Match(buffer []byte)	(bool,[]Target,[]byte) {
	if Verbose {
		fmt.Printf("single_cs\t-> %d | %d\n", len(abnf.tokens), len(buffer) )
		fmt.Printf("\t\t-> [%s]\n", string(abnf.abnf) )
		fmt.Printf("\t\t-> [%s]\n", string(buffer) )
	}

	if len(abnf.tokens) > len(buffer) {
		return false, []Target{ }, buffer
	}

	for i,tok := range abnf.tokens {
		if tok != buffer[i] {
			return	false, []Target{ }, buffer
		}
	}

	if Verbose {
		fmt.Printf("\t\t-> [%s]\n", buffer[0:len(abnf.tokens)] )
	}

	return	true, []Target{ { Value: buffer[0:len(abnf.tokens)] } }, buffer[len(abnf.tokens):]
}





func	single_byte(single ...byte) Expression {
	return &ABNF_Single_byte {
		abnf: abnf_single_byte(single),
		tokens: single,
	}
}

func	mutator_byte(expr Expression) Expression {
	switch expr.(type) {
		case *ABNF_Single_byte:
			return expr

		case *ABNF_Single_ci:
			tokens := expr.(*ABNF_Single_ci).tokens
			return &ABNF_Single_byte {
				abnf: abnf_single_byte(tokens),
				tokens: tokens,
			}

		case *ABNF_Single_cs:
			tokens := expr.(*ABNF_Single_cs).tokens
			return &ABNF_Single_byte {
				abnf: abnf_single_byte(tokens),
				tokens: tokens,
			}
	}
	panic("WTF !"+expr.ABNF())
}




func	(abnf *ABNF_Single_byte)ABNF()	string {
	return abnf.abnf
}

func	(abnf *ABNF_Single_byte)Match(buffer []byte)	(bool,[]Target,[]byte) {
	if Verbose {
		fmt.Printf("single_byte\t-> %d | %d\n", len(abnf.tokens), len(buffer) )
		fmt.Printf("\t\t-> [%s]\n", string(abnf.abnf) )
		fmt.Printf("\t\t-> [%s]\n", string(buffer) )
	}

	if len(abnf.tokens) > len(buffer) {
		return false, []Target{ }, buffer
	}

	for i,tok := range abnf.tokens {
		if tok != buffer[i] {
			return	false, []Target{ }, buffer
		}
	}

	if Verbose {
		fmt.Printf("\t\t-> [%s]\n", buffer[0:len(abnf.tokens)] )
	}

	return	true, []Target{ { Value: buffer[0:len(abnf.tokens)] } }, buffer[len(abnf.tokens):]
}
