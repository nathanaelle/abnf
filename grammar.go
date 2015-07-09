package abnf	// import "github.com/nathanaelle/abnf"
import	(
	"sync"
	"strings"
	"sort"
	// "log"
)

//	a Grammar is a map between the names and expressions
type	Grammar 	struct {
	start	string
	tokens	map[string]Expression
	glock	sync.Mutex
}


func NewGrammar(start string) *Grammar {
	// log.SetFlags(log.Lshortfile)
	g := new(Grammar)
	g.start = start
	g.tokens = make(map[string]Expression)
	return g
}


func (g Grammar)String() string {
	ret := make([]string,0,len(g.tokens))

	for _,token := range g.tokens {
		ret = append(ret, token.ABNF())
	}

	sort.Strings(ret)
	return strings.Join(ret, "\r\n")+"\r\n"
}


func (g Grammar)Valid(buffer []byte) (bool,Target) {
	if start,ok := g._get_token(g.start); ok {
		valid,t,end := start.Match(buffer)

		if valid && len(end) == 0 {
			return true, Target{ Childs: t }			
		}
		return false, Target{ Childs: t, Value: end }

	}

	panic("unkown rule : "+ g.start)
}



func (g Grammar)set(name string, expr Expression) {
	g.glock.Lock()
	defer g.glock.Unlock()
	k := strings.ToUpper(name)

	if _,ok := g.tokens[k]; ok {
		panic("token already set : "+name)
	}

	g.tokens[k] = &ABNF_Assign {
		abnf: name + " = " + expr.ABNF(),
		expr: expr,
	}
}

func (g Grammar)_get_token(name string) (Expression,bool) {
	k := strings.ToUpper(name)

	g.glock.Lock()
	ret,ok := g.tokens[k];
	g.glock.Unlock()

	return ret,ok
}

func (g Grammar)get(name string) Expression {
	return &ABNF_Ref {
		abnf: name,
		get: func() Expression {
			if ret,ok := g._get_token(name); ok {
				return ret
			}
			panic("expression doesn't exist : "+ name)
		},
	}
}


func (g Grammar)def_get(name string) Expression {
	if ret,ok := g._get_token(name); ok {
		return ret
	}

	panic("expression doesn't exist : "+ name)
}
