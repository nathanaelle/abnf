package abnf	// import "github.com/nathanaelle/abnf"

import	(
	"fmt"
	"strconv"
	"strings"
)


var Verbose bool


type	ABNFEngine struct {
	*Grammar
}


func ABNF() ABNFEngine {
	g := NewGrammar("rulelist")

	g.set("alpha"	,choice(extents('A','Z'),extents('a','z')))		// A-Z / a-z
	g.set("bit"	,choice(single_ci('0'),single_ci('1')))
	g.set("char"	,extents(0x01,0x7F))					// any 7-bit US-ASCII character excluding NUL
	g.set("cr"	,single_byte(0x0D))						// carriage return
	g.set("lf"	,single_byte(0x0A))						// linefeed
	g.set("crlf"	,concat(g.get("cr"), g.get("lf")))			// Internet standard newline
	g.set("CTL"	,choice(extents(0x00,0x1F), single_byte(0x7F)))		// controls
	g.set("digit"	,extents('0','9'))					// 0-9
	g.set("hexdig"	,choice(g.get("digit"),single_ci('A'),single_ci('B'),single_ci('C'),single_ci('D'),single_ci('E'),single_ci('F')))
	g.set("dquote"	,single_byte(0x22))						// " (Double Quote)
	g.set("octet"	,extents(0x00,0xFF))					// 8 bits of data
	g.set("vchar"	,extents(0x21,0x7E))					// visible (printing) characters
	g.set("htab"	,single_byte(0x09))						// horizontal tab
	g.set("sp"	,single_byte(0x20))
	g.set("wsp"	,choice(g.get("sp"),g.get("htab")))			// white space

	// Use of this linear-white-space rule
	//  permits lines containing only white
	//  space that are no longer legal in
	//  mail headers and have caused
	//  interoperability problems in other
	//  contexts.
	// Do not use when defining mail headers and use with caution in other contexts.
	g.set("lwsp"	,star(0,0,group(choice(g.get("wsp"), concat(g.get("crlf"),g.get("wsp"))))))

	// bracketed string of SP and VCHAR without angles
	// prose description, to be used as last resort
	g.set("prose-val", concat(single_ci('<'), star(0,0,group(choice(extents(0x20,0x3D), extents(0x3F,0x7E)))), single_ci('>')))

	// series of concatenated bit values or single ONEOF range
	g.set("bin-val", concat(single_ci('b'), star(1,0, g.get("bit") ), option( star(1,0,choice(group(single_ci('.'), star(1,0, g.get("bit") )), group(single_ci('-'),star(1,0, g.get("bit") )))))))
	g.set("dec-val", concat(single_ci('d'), star(1,0, g.get("digit") ), option( star(1,0,choice(group(single_ci('.'), star(1,0, g.get("digit") )), group(single_ci('-'),star(1,0, g.get("digit") )))))))
	g.set("hex-val", concat(single_ci('x'), star(1,0, g.get("hexdig") ), option( star(1,0,choice(group(single_ci('.'), star(1,0, g.get("hexdig") )), group(single_ci('-'),star(1,0, g.get("hexdig") )))))))
	g.set("num-val", concat(single_ci('%'), group(choice( g.get("bin-val") , g.get("dec-val") , g.get("hex-val") ))))


	// quoted string of SP and VCHAR without DQUOTE
	g.set("quoted-string", concat( g.get("dquote") , star(0,0,group(choice(extents(0x20,0x21), extents(0x23,0x7E)))), g.get("dquote") ))
	g.set("case-insensitive-string", concat(option(single_ci('%','i')), g.get("quoted-string")))
	g.set("case-sensitive-string", concat(single_ci('%','s'), g.get("quoted-string")))
	g.set("char-val", choice(g.get("Case-insensitive-string"),g.get("Case-sensitive-string")))

	g.set("comment", concat(single_ci(';'), star(0,0,group(choice( g.get("wsp") , g.get("vchar") ))),  g.get("crlf") ))
	g.set("c-nl", choice( g.get("comment") , g.get("crlf") )) // comment or newline
	g.set("c-wsp", choice( g.get("wsp") , group( g.get("c-nl") , g.get("wsp") ) ))

	g.set("group", concat( single_ci('('), star(0,0, g.get("c-wsp") ), g.get("Alternation") ,star(0,0, g.get("c-wsp") ), single_ci(')')))
	g.set("option", concat( single_ci('['), star(0,0, g.get("c-wsp") ), g.get("Alternation") ,star(0,0, g.get("c-wsp") ), single_ci(']')))
	g.set("element", choice( g.get("Rulename") , g.get("Group") , g.get("Option") , g.get("Char-val") , g.get("Num-val") , g.get("Prose-val") ))
	g.set("repeat", choice( star(1,0, g.get("digit")), group( star(0,0, g.get("digit")), single_ci('*'), star(0,0, g.get("digit")) )))
	g.set("repetition", concat(option( g.get("Repeat") ), g.get("Element") ))
	g.set("concatenation", concat( g.get("Repetition") , star(0,0,group(star(1,0, g.get("c-wsp") ), g.get("Repetition") ))))
	g.set("alternation", concat( g.get("Concatenation") , star(0,0,group(star(0,0, g.get("c-wsp") ), single_ci('/'), star(0,0, g.get("c-wsp") ), g.get("Concatenation") ))))
	g.set("elements", concat( g.get("Alternation") , star(0,0, g.get("wsp") )))

	// basic rules definition and incremental alternatives
	g.set("defined-as", concat(star(0,0, g.get("c-wsp") ), group(choice(single_ci('='),single_ci('=','/'))), star(0,0, g.get("c-wsp") )))
	g.set("rulename", concat( g.get("alpha") , star(0,0,group( choice( g.get("alpha") , g.get("digit") , single_ci('-'))))))

	// continues if next line starts with white space
	g.set("rule", concat( g.get("Rulename") , g.get("Defined-as")  , g.get("Elements") , g.get("c-nl") ))
	g.set("rulelist", star(1,0,group(choice( g.get("Rule") , group(star(0,0, g.get("wsp") ), g.get("c-nl") )))))

	return ABNFEngine { g }
}



func (ABNFEngine) Compile(T Target, start string) *Grammar {
	g := NewGrammar(start)

	cleaned_target := T.Drop("c-wsp","c-nl").Merge("Defined-as","Rulename","dquote","digit","hexdig","quoted-string","alpha","")

	for _,rule := range cleaned_target.Childs {
		switch string(rule.Childs[1].Value) {
			case "=":	g.set(string(rule.Childs[0].Value), compile(g,rule.Childs[2]))
			default:	panic("don't know hwo to : "+ rule.String())
		}
	}

	return g
}


func to_int(b[]byte,base int) int {
	v,_ := strconv.ParseInt(string(b), base, 64)
	return int(v)
}

func to_byte(b[]byte,base int) byte {
	v,_ := strconv.ParseInt(string(b), base, 64)
	return byte(v)
}






func compile(g *Grammar, target Target) Expression {
	switch strings.ToUpper(target.Rule) {
		case	"RULENAME":
			return g.get(string(target.Value))

		case	"GROUP":
			return group(compile(g,target.Childs[1]))

		case	"OPTION":
			return option(compile(g,target.Childs[1]))

		case	"ALTERNATION":
			exprs := []Expression {}
			for i,c := range target.Childs {
				if i%2 == 0 {
					exprs = append(exprs, compile(g,c))
				}
			}

			return choice(exprs...)

		case	"CONCATENATION":
			exprs := []Expression {}
			for _,c := range target.Childs {
				exprs = append(exprs, compile(g,c))
			}

			return concat(exprs...)


		case	"REPETITION":
			if len(target.Childs) == 1 {
				return star(1,1,compile(g,target.Childs[0]))
			}

			repeat := target.Childs[0]
			min := 0
			max := 0
			switch len(repeat.Childs){
				case	3:
					min = to_int(repeat.Childs[0].Value,10)
					max = to_int(repeat.Childs[2].Value,10)

				case	2:
					if(string(repeat.Childs[1].Value) == "*"){
						min = to_int(repeat.Childs[0].Value,10)
					} else {
						max = to_int(repeat.Childs[1].Value,10)
					}

				case	1:
					if(string(repeat.Childs[0].Value) != "*"){
						min = to_int(repeat.Childs[0].Value,10)
						max = to_int(repeat.Childs[0].Value,10)
					}
			}

			return star(min,max,compile(g,target.Childs[1]))


		case	"QUOTED-STRING":
			return single_ci(target.Value[1:len(target.Value)-1]...)

		case	"CASE-INSENSITIVE-STRING":
			return mutator_ci(compile(g,target.Childs[len(target.Childs)-1]))

		case	"CASE-SENSITIVE-STRING":
			return mutator_cs(compile(g,target.Childs[1]))

		case	"NUM-VAL":
			return compile(g,target.Childs[1])

		case	"HEX-VAL":
			if len(target.Childs) == 2 {
				min := to_byte(target.Childs[1].Value,16)
				return single_byte(min)
			}

			if len(target.Childs) == 4 && string(target.Childs[2].Value) == "-" {
				min := to_byte(target.Childs[1].Value,16)
				max := to_byte(target.Childs[3].Value,16)
				return extents(min,max)
			}
			panic("Don't know how to cope with "+target.String() )

		case	"DEC-VAL":
			if len(target.Childs) == 2 {
				min := to_byte(target.Childs[1].Value,10)
				return single_byte(min)
			}

			if len(target.Childs) == 4 && string(target.Childs[2].Value) == "-" {
				min := to_byte(target.Childs[1].Value,10)
				max := to_byte(target.Childs[3].Value,10)
				return extents(min,max)
			}
			panic("Don't know how to cope with "+target.String() )


		default:
			if len(target.Childs) > 0 && len(target.Value) > 0 {
				panic("Don't know how to cope with "+target.String() )
			}

			if len(target.Childs) == 0 && len(target.Value) == 0 {
				panic("Don't know how to cope with "+target.String() )
			}


			if len(target.Childs) == 0 && len(target.Value) > 0 {
				return single_cs(target.Value...)
			}

			if len(target.Childs) == 1 {
				return compile(g,target.Childs[0])
			}

			fmt.Println("Don't know how to cope with "+target.Rule )
			for _,c := range target.Childs {
				fmt.Println("[", c.String() ,"]")
			}
			panic("Don't know how to cope with "+target.String() )
	}
}
