package abnf

import (
	"testing"
	"strings"
)



func compile_new_ABNF_compilator(build string,t *testing.T, abnf ABNFEngine, text_grammar string ) ABNFEngine {
	valid_ABNF,tree := abnf.Valid([]byte(text_grammar))
	if !valid_ABNF {
		t.Errorf("build -> [%s], errors found in \n%s\n---------------------------\n", build, text_grammar)
		for _,c := range tree.Childs {
			t.Logf("[%s]\n", c.String())
		}
		t.Logf("--[%s]--\n", string(tree.Value))
	}

	return ABNFEngine { abnf.Compile(tree,"rulelist") }
}


func Test_ABNF_for_7405(t *testing.T) {
	sorted_ABNF_7405:= normalize(strings.ToUpper(ABNF_ABNF_7405))

	// using standard ABNF to create a new ABNF compilator abnf_1
	abnf_1 := compile_new_ABNF_compilator("1", t, ABNF(), sorted_ABNF_7405 )

	// using custom abnf_1 compilator to compile a new custome compilator abnf_2
	abnf_2 := compile_new_ABNF_compilator("2", t, abnf_1, sorted_ABNF_7405 )

	// using custom abnf_2 compilator to compile a new custome compilator abnf_3
	abnf_3 := compile_new_ABNF_compilator("3", t, abnf_2, sorted_ABNF_7405 )

	// using custom abnf_3 compilator to compile a new custome compilator abnf_4
	abnf_4 := compile_new_ABNF_compilator("4", t, abnf_3, sorted_ABNF_7405 )

	sorted_ABNF	:= normalize(strings.ToUpper(abnf_4.String()))

	if sorted_ABNF != sorted_ABNF_7405 {
		t.Errorf("build -> [%s], difference between \n---------\n%s\n---------\nand\n---------\n%s\n---------\n ", sorted_ABNF_7405, sorted_ABNF )
	}
}



func Test_ABNF_for_5234(t *testing.T) {
	sorted_ABNF_5234:= normalize(strings.ToUpper(ABNF_ABNF_5234))

	// using standard ABNF to create a new ABNF compilator abnf_1
	abnf_1 := compile_new_ABNF_compilator("1", t, ABNF(), sorted_ABNF_5234 )

	// using custom abnf_1 compilator to compile a new custome compilator abnf_2
	abnf_2 := compile_new_ABNF_compilator("2", t, abnf_1, sorted_ABNF_5234 )

	// using custom abnf_2 compilator to compile a new custome compilator abnf_3
	abnf_3 := compile_new_ABNF_compilator("3", t, abnf_2, sorted_ABNF_5234 )

	// using custom abnf_3 compilator to compile a new custome compilator abnf_4
	abnf_4 := compile_new_ABNF_compilator("4", t, abnf_3, sorted_ABNF_5234 )

	sorted_ABNF	:= normalize(strings.ToUpper(abnf_4.String()))

	if sorted_ABNF != sorted_ABNF_5234 {
		t.Errorf("build -> [%s], difference between \n---------\n%s\n---------\nand\n---------\n%s\n---------\n ", sorted_ABNF_5234, sorted_ABNF )
	}
}





func Test_ABNF_for_Everyone(t *testing.T) {
	sorted_ABNF_7405:= normalize(strings.ToUpper(ABNF_ABNF_7405))
	sorted_ABNF_5234:= normalize(strings.ToUpper(ABNF_ABNF_5234))

	// using standard ABNF to create a new ABNF compilator abnf_1
	abnf_1 := compile_new_ABNF_compilator("1", t, ABNF(), sorted_ABNF_5234 )

	// using custom abnf_1 compilator to compile a new custome compilator abnf_2
	abnf_2 := compile_new_ABNF_compilator("2", t, abnf_1, sorted_ABNF_7405 )

	// using custom abnf_2 compilator to compile a new custome compilator abnf_3
	abnf_3 := compile_new_ABNF_compilator("3", t, abnf_2, sorted_ABNF_5234 )

	// using custom abnf_3 compilator to compile a new custome compilator abnf_4
	abnf_4 := compile_new_ABNF_compilator("4", t, abnf_3, sorted_ABNF_7405 )

	sorted_ABNF	:= normalize(strings.ToUpper(abnf_4.String()))

	if sorted_ABNF != sorted_ABNF_7405 {
		t.Errorf("build -> [%s], difference between \n---------\n%s\n---------\nand\n---------\n%s\n---------\n ", sorted_ABNF_7405, sorted_ABNF )
	}

}
