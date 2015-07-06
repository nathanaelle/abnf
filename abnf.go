package abnf	// import "github.com/nathanaelle/abnf"

func ABNF() *Grammar {
	g := NewGrammar("rulelist")

	// RFC 5234 errata 2968 3076 applied
	g.set("ALPHA"	,choice(extent('A','Z'),extent('a','z')))		// A-Z / a-z
	g.set("BIT"	,choice(single('0'),single('1')))
	g.set("CHAR"	,extent(0x01,0x7F))					// any 7-bit US-ASCII character excluding NUL
	g.set("CR"	,single(0x0D))						// carriage return
	g.set("LF"	,single(0x0A))						// linefeed
	g.set("CRLF"	,concat(g.get("CR"), g.get("LF")))			// Internet standard newline
	g.set("CTL"	,choice(extent(0x00,0x1F), single(0x7F)))		// controls
	g.set("DIGIT"	,extent('0','9'))					// 0-9
	g.set("HEXDIG"	,choice(g.get("DIGIT"),single('A'),single('B'),single('C'),single('D'),single('E'),single('F')))
	g.set("DQUOTE"	,single(0x22))						// " (Double Quote)
	g.set("OCTET"	,extent(0x00,0xFF))					// 8 bits of data
	g.set("VCHAR"	,extent(0x21,0x7E))					// visible (printing) characters
	g.set("HTAB"	,single(0x09))						// horizontal tab
	g.set("SP"	,single(0x20))
	g.set("WSP"	,choice(g.get("SP"),g.get("HTAB")))			// white space

	// Use of this linear-white-space rule
	//  permits lines containing only white
	//  space that are no longer legal in
	//  mail headers and have caused
	//  interoperability problems in other
	//  contexts.
	// Do not use when defining mail
	//  headers and use with caution in
	//  other contexts.
	g.set("LWSP"	,star(0,0,group(choice(g.get("WSP"), concat(g.get("CRLF"),g.get("WSP"))))))

	// bracketed string of SP and VCHAR
	//  without angles
	// prose description, to be used as
	//  last resort
	g.set("prose-val", concat(single('<'), star(0,0,group(choice(extent(0x20,0x3D), extent(0x3F,0x7E)))), single('>')))

	// series of concatenated bit values
	//  or single ONEOF range
	g.set("bin-val", concat(single('b'), star(1,0, g.get("BIT") ), option( star(1,0,choice(group(single('.'), star(1,0, g.get("BIT") )), group(single('-'),star(1,0, g.get("BIT") )))))))
	g.set("dec-val", concat(single('d'), star(1,0, g.get("DIGIT") ), option( star(1,0,choice(group(single('.'), star(1,0, g.get("DIGIT") )), group(single('-'),star(1,0, g.get("DIGIT") )))))))
	g.set("hex-val", concat(single('x'), star(1,0, g.get("HEXDIG") ), option( star(1,0,choice(group(single('.'), star(1,0, g.get("HEXDIG") )), group(single('-'),star(1,0, g.get("HEXDIG") )))))))
	g.set("num-val", concat(single('%'), group(choice( g.get("bin-val") , g.get("dec-val") , g.get("hex-val") ))))

	// quoted string of SP and VCHAR
	//  without DQUOTE
	g.set("char-val", concat( g.get("DQUOTE") , star(0,0,group(choice(extent(0x20,0x21), extent(0x23,0x7E)))), g.get("DQUOTE") ))

	g.set("comment", concat(single(';'), star(0,0,group(choice( g.get("WSP") , g.get("VCHAR") ))),  g.get("CRLF") ))
	g.set("c-nl", choice( g.get("comment") , g.get("CRLF") )) // comment or newline
	g.set("c-wsp", choice( g.get("WSP") , group( g.get("c-nl") , g.get("WSP") ) ))

	g.set("group", concat( single('('), star(0,0, g.get("c-wsp") ), g.get("alternation") ,star(0,0, g.get("c-wsp") ), single(')')),)
	g.set("option", concat( single('['), star(0,0, g.get("c-wsp") ), g.get("alternation") ,star(0,0, g.get("c-wsp") ), single(']')),)
	g.set("element", choice( g.get("rulename") , g.get("group") , g.get("option") , g.get("char-val") , g.get("num-val") , g.get("prose-val") ))
	g.set("repeat", choice( star(1,0, g.get("DIGIT")), group( star(0,0, g.get("DIGIT")), single('*'), star(0,0, g.get("DIGIT")) )))
	g.set("repetition", concat(option( g.get("repeat") ), g.get("element") ))
	g.set("concatenation", concat( g.get("repetition") , star(0,0,group(star(1,0, g.get("c-wsp") ), g.get("repetition") ))),)
	g.set("alternation", concat( g.get("concatenation") , star(0,0,group(star(0,0, g.get("c-wsp") ), single('/'), star(0,0, g.get("c-wsp") ), g.get("concatenation") ))))
	g.set("elements", concat( g.get("alternation") , star(0,0, g.get("WSP") )))

	// basic rules definition and
	//  incremental alternatives
	g.set("defined-as", concat(star(0,0, g.get("c-wsp") ), group(choice(single('='),single('=','/'))), star(0,0, g.get("c-wsp") )))
	g.set("rulename", concat( g.get("ALPHA") , star(0,0,group( choice( g.get("ALPHA") , g.get("DIGIT") , single('-'))))))

	// continues if next line starts
	//  with white space
	g.set("rule", concat( g.get("rulename") , g.get("defined-as")  , g.get("elements") , g.get("c-nl") ))
	g.set("rulelist", star(1,0,group(choice( g.get("rule") , group(star(0,0, g.get("WSP") ), g.get("c-nl") )))))

	return g
}
