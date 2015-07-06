package abnf	// import "github.com/nathanaelle/abnf"
import	(
	"strings"
	"fmt"
)

type(
	Expression	struct {
		abnf			string
		match 			func([]byte)(bool,[]byte,[]byte)
	}

)


func	(exp Expression)ABNF()	string {
	return exp.abnf
}

func	(exp Expression)Match(buffer []byte)	(bool,[]byte,[]byte) {
	return exp.match(buffer)
}

func	(exp Expression)Verify(buffer []byte)	(bool) {
	r,_,_ := exp.match(buffer)
	return r
}


func abnfs(exprs []Expression) []string {
	ret := make([]string,len(exprs))
	for i,expr := range exprs {
		ret[i] = expr.ABNF()
	}
	return ret
}




func abnf_single_tok(b byte)(bool,string){
	// Holly shit ! I'm too tired to write the correct code so I use this stoopid switch
	switch {
		case b>='0' && b<='9':		return true,string([]byte{b})
		case b>='A' && b<='Z':		return true,string([]byte{b})
		case b>='a' && b<='z':		return true,string([]byte{b})
		case b=='(' || b==')':		return true,string([]byte{b})
		case b=='{' || b=='}':		return true,string([]byte{b})
		case b=='[' || b==']':		return true,string([]byte{b})
		case b=='<' || b=='>':		return true,string([]byte{b})
		case b=='!':			return true,string([]byte{b})
		case b=='.':			return true,string([]byte{b})
		case b=='-':			return true,string([]byte{b})
		case b=='%':			return true,string([]byte{b})
		case b==';':			return true,string([]byte{b})
		case b=='=':			return true,string([]byte{b})
		case b=='/':			return true,string([]byte{b})
		case b=='*':			return true,string([]byte{b})
		default:			return false,fmt.Sprintf("%%x%02X",b)
	}
}


func abnf_single(tokens []byte) string {
	ret := ""
	quote_prev := false
	init := true

	for _,tok := range tokens {
		q, buff := abnf_single_tok(tok)
		switch {
			case init && !q:
				init = false
				ret = buff

			case init &&  q:
				quote_prev = true
				init = false
				ret = "\""+buff

			case  quote_prev &&  q:
				ret = ret+buff

			case !quote_prev && !q:
				ret = ret+" "+buff

			case !quote_prev &&  q:
				quote_prev = true
				ret = ret+" \""+buff

			case quote_prev &&  !q:
				quote_prev = false
				ret = ret+"\" "+buff
		}
	}
	if quote_prev {
		ret = ret + "\""
	}

	return ret
}


func	single(single ...byte) Expression {
	return Expression {
		abnf: abnf_single(single),
		match: func(buffer []byte) (bool,[]byte,[]byte) {
			if len(single) > len(buffer) {
				return false, []byte{ }, buffer
			}

			for i,_ := range single {
				if single[i] != buffer[i] {
					return	false, []byte{ }, buffer
				}
			}
			return	true, buffer[0:len(single)], buffer[len(single):]
		},
	}
}

func	extent(start,last byte) Expression {
	return Expression {
		abnf: fmt.Sprintf("%%x%02X-%02X",start, last),
		match: func(buffer []byte) (bool,[]byte,[]byte) {
			if buffer[0] >= start && buffer[0] <= last {
				return	true, buffer[0:1], buffer[1:]
			}

			return	false, []byte{ }, buffer
		},
	}
}

func choice(exprs ...Expression) Expression {
	return Expression {
		abnf: strings.Join( abnfs(exprs)," / "),
		match: func(buffer []byte) (bool,[]byte,[]byte) {
			// " / " works right to left … not left to right like the rest
			for i:=len(exprs)-1; i>=0 ; i-- {
				if ok, buff,end := exprs[i].Match(buffer); ok {
					return ok, buff, end
				}
			}

			return	false, []byte{ }, buffer
		},
	}
}

func concat(exprs ...Expression) Expression {
	return Expression {
		abnf: strings.Join( abnfs(exprs)," "),
		match: func(buffer []byte) (bool,[]byte,[]byte) {
			end	:= buffer
			resp	:= []byte{}
			for _,exp := range exprs {
				var ok		bool
				var t_resp	[]byte

				ok,t_resp,end = exp.Match(end);
				if  !ok {
					return	false, []byte{ }, buffer
				}
				resp = append(resp, t_resp...)
			}
			return true,resp,end
		},
	}
}

func group(exprs ...Expression) Expression {
	return Expression {
		abnf: "(" + strings.Join( abnfs(exprs)," ") + ")",
		match: func(buffer []byte) (bool,[]byte,[]byte) {
			end	:= buffer
			resp	:= []byte{}
			for _,exp := range exprs {
				var ok		bool
				var t_resp	[]byte

				ok,t_resp,end = exp.Match(end);
				if  !ok {
					return	false, []byte{ }, buffer
				}
				resp = append(resp, t_resp...)
			}
			return true,resp,end
		},
	}
}




func abnf_star(min ,max int,b string) string {
	switch {
		case min == 0 && max == 0:	return fmt.Sprintf("*%s",b)
		case min == max:		return fmt.Sprintf("%d %s",min,b)
		case min == 0:			return fmt.Sprintf("%d %s",max,b)
		case max == 0:			return fmt.Sprintf("%d*%s",min,b)
		default:			return fmt.Sprintf("%d*%d %s",min,max,b)
	}
}

func star(min ,max int, expr Expression) Expression {
	return Expression {
		abnf: abnf_star(min,max, expr.ABNF()),
		match: func(buffer []byte) (bool,[]byte,[]byte) {
			idx	:= 0
			end	:= buffer
			resp	:= []byte{}

			for {
				ok,t_resp,t_end := expr.Match(end);
				if  !ok {
					break
				}
				idx++
				resp	= append(resp, t_resp...)
				end	= t_end
				if idx == max {
					break
				}
				if(len(end)==0){
					break
				}
			}

			if idx < min {
				return	false, []byte{ }, buffer
			}

			return true, resp, end
		},
	}
}


func option(expr Expression) Expression {
	return Expression {
		abnf: "[ "+ expr.ABNF() +" ]",
		match: func(buffer []byte) (bool,[]byte,[]byte) {
			ok,resp,end := expr.Match(buffer);
			if  !ok {
				return true, []byte{}, buffer
			}
			return true, resp, end
		},
	}
}
