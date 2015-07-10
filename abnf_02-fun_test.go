package abnf

import (
	"testing"
	"strings"
)



func compile_new_ABNF_compilator(t *testing.T, abnf ABNFEngine, text_grammar string ) ABNFEngine {
	valid_ABNF,tree := ABNF().Valid([ ]byte(text_grammar))
	if !valid_ABNF {
		t.Errorf("errors found in \n---------\n%s\n---------\n", text_grammar)
	}

	return ABNFEngine { ABNF().Compile(tree,"record") }
}


func Test_ABNF_for_EveryOne(t *testing.T) {
	sorted_ABNF_7405:= normalize(strings.ToUpper(ABNF_ABNF_7405))
	sorted_ABNF_5234:= normalize(strings.ToUpper(ABNF_ABNF_5234))

	// using standard ABNF to create a new ABNF compilator abnf_1
	abnf_1 := compile_new_ABNF_compilator( t, ABNF(), sorted_ABNF_5234 )

	// using custom abnf_1 compilator to compile a new custome compilator abnf_2
	abnf_2 := compile_new_ABNF_compilator( t, abnf_1, sorted_ABNF_7405 )

	// using custom abnf_2 compilator to compile a new custome compilator abnf_3
	abnf_3 := compile_new_ABNF_compilator( t, abnf_2, sorted_ABNF_5234 )

	// using custom abnf_3 compilator to compile a new custome compilator abnf_4
	abnf_4 := compile_new_ABNF_compilator( t, abnf_3, sorted_ABNF_7405 )

	sorted_ABNF	:= normalize(strings.ToUpper(abnf_4.String()))

	if sorted_ABNF != sorted_ABNF_7405 {
		t.Errorf("difference between \n---------\n%s\n---------\nand\n---------\n%s\n---------\n ", sorted_ABNF_7405, sorted_ABNF )
	}

}
