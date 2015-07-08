package abnf	// import "github.com/nathanaelle/abnf"

func ABNF() *Grammar {
	g := NewGrammar("rulelist")

	g.set("ALPHA"	,choice(extents('A','Z'),extents('a','z')))		// A-Z / a-z
	g.set("BIT"	,choice(single_ci('0'),single_ci('1')))
	g.set("CHAR"	,extents(0x01,0x7F))					// any 7-bit US-ASCII character excluding NUL
	g.set("CR"	,single_byte(0x0D))						// carriage return
	g.set("LF"	,single_byte(0x0A))						// linefeed
	g.set("CRLF"	,concat(g.get("CR"), g.get("LF")))			// Internet standard newline
	g.set("CTL"	,choice(extents(0x00,0x1F), single_byte(0x7F)))		// controls
	g.set("DIGIT"	,extents('0','9'))					// 0-9
	g.set("HEXDIG"	,choice(g.get("DIGIT"),single_ci('A'),single_ci('B'),single_ci('C'),single_ci('D'),single_ci('E'),single_ci('F')))
	g.set("DQUOTE"	,single_byte(0x22))						// " (Double Quote)
	g.set("OCTET"	,extents(0x00,0xFF))					// 8 bits of data
	g.set("VCHAR"	,extents(0x21,0x7E))					// visible (printing) characters
	g.set("HTAB"	,single_byte(0x09))						// horizontal tab
	g.set("SP"	,single_byte(0x20))
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
	g.set("prose-val", concat(single_ci('<'), star(0,0,group(choice(extents(0x20,0x3D), extents(0x3F,0x7E)))), single_ci('>')))

	// series of concatenated bit values
	//  or single ONEOF range
	g.set("bin-val", concat(single_ci('b'), star(1,0, g.get("BIT") ), option( star(1,0,choice(group(single_ci('.'), star(1,0, g.get("BIT") )), group(single_ci('-'),star(1,0, g.get("BIT") )))))))
	g.set("dec-val", concat(single_ci('d'), star(1,0, g.get("DIGIT") ), option( star(1,0,choice(group(single_ci('.'), star(1,0, g.get("DIGIT") )), group(single_ci('-'),star(1,0, g.get("DIGIT") )))))))
	g.set("hex-val", concat(single_ci('x'), star(1,0, g.get("HEXDIG") ), option( star(1,0,choice(group(single_ci('.'), star(1,0, g.get("HEXDIG") )), group(single_ci('-'),star(1,0, g.get("HEXDIG") )))))))
	g.set("num-val", concat(single_ci('%'), group(choice( g.get("bin-val") , g.get("dec-val") , g.get("hex-val") ))))


	// quoted string of SP and VCHAR
	//  without DQUOTE
	g.set("quoted-string", concat( g.get("DQUOTE") , star(0,0,group(choice(extents(0x20,0x21), extents(0x23,0x7E)))), g.get("DQUOTE") ))
	g.set("case-insensitive-string", concat(option(single_ci('%','i')), g.get("quoted-string")))
	g.set("case-sensitive-string", concat(single_ci('%','s'), g.get("quoted-string")))
	g.set("char-val", choice(g.get("case-insensitive-string"),g.get("case-sensitive-string")))

	g.set("comment", concat(single_ci(';'), star(0,0,group(choice( g.get("WSP") , g.get("VCHAR") ))),  g.get("CRLF") ))
	g.set("c-nl", choice( g.get("comment") , g.get("CRLF") )) // comment or newline
	g.set("c-wsp", choice( g.get("WSP") , group( g.get("c-nl") , g.get("WSP") ) ))

	g.set("group", concat( single_ci('('), star(0,0, g.get("c-wsp") ), g.get("alternation") ,star(0,0, g.get("c-wsp") ), single_ci(')')),)
	g.set("option", concat( single_ci('['), star(0,0, g.get("c-wsp") ), g.get("alternation") ,star(0,0, g.get("c-wsp") ), single_ci(']')),)
	g.set("element", choice( g.get("rulename") , g.get("group") , g.get("option") , g.get("char-val") , g.get("num-val") , g.get("prose-val") ))
	g.set("repeat", choice( star(1,0, g.get("DIGIT")), group( star(0,0, g.get("DIGIT")), single_ci('*'), star(0,0, g.get("DIGIT")) )))
	g.set("repetition", concat(option( g.get("repeat") ), g.get("element") ))
	g.set("concatenation", concat( g.get("repetition") , star(0,0,group(star(1,0, g.get("c-wsp") ), g.get("repetition") ))),)
	g.set("alternation", concat( g.get("concatenation") , star(0,0,group(star(0,0, g.get("c-wsp") ), single_ci('/'), star(0,0, g.get("c-wsp") ), g.get("concatenation") ))))
	g.set("elements", concat( g.get("alternation") , star(0,0, g.get("WSP") )))

	// basic rules definition and
	//  incremental alternatives
	g.set("defined-as", concat(star(0,0, g.get("c-wsp") ), group(choice(single_ci('='),single_ci('=','/'))), star(0,0, g.get("c-wsp") )))
	g.set("rulename", concat( g.get("ALPHA") , star(0,0,group( choice( g.get("ALPHA") , g.get("DIGIT") , single_ci('-'))))))

	// continues if next line starts
	//  with white space
	g.set("rule", concat( g.get("rulename") , g.get("defined-as")  , g.get("elements") , g.get("c-nl") ))
	g.set("rulelist", star(1,0,group(choice( g.get("rule") , group(star(0,0, g.get("WSP") ), g.get("c-nl") )))))

	return g
}
