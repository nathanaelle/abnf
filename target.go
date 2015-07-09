package abnf	// import "github.com/nathanaelle/abnf"
import	(
)

func inSlice(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}

type	Target		struct {
	Childs	[]Target
	Rule	string
	Value	[]byte
}



func (t Target) String() string {
	if t.Rule != "" {
		val := " "+t.Rule+"={"+string(t.Value)
		for _,child := range t.Childs {
			val= val+child.String()
		}

		return val+"}"
	}

	//if len(t.Childs) == 0 {
	//	return string(t.Value)
	//}

	val := "{"+string(t.Value)
	for _,child := range t.Childs {
		val= val+child.String()
	}

	return val+"}"
}


func (t Target) Drop(rules ...string) Target {
	childs := []Target {}
	for _,target := range t.Childs {
		if !inSlice(target.Rule, rules) {
			childs = append(childs, target.Drop(rules...))
		}
	}
	return Target { childs, t.Rule, t.Value }
}



func merge_leaf(targets ...Target) []Target {
	value	:= []byte{}
	for _,c := range targets {
		if len(c.Childs) > 0 {
			return targets
		}
		value = append(value, c.Value... )
	}
	return []Target {{ []Target{}, targets[0].Rule, value }}
}


func (target Target) Merge(rules ...string) Target {
	if len(target.Childs) == 0 {
		return target
	}

	t_childs := []Target{}
	for _,c := range target.Childs {
		t_childs = append(t_childs, c.Merge(rules...) )
	}

	childs	:= []Target{}
	tmp_t	:= Target{}
	for i,t_c := range t_childs {
		if i==0{
			tmp_t = t_c
			continue
		}
		if tmp_t.Rule != t_c.Rule {
			childs = append(childs, tmp_t )
			tmp_t = t_c
			continue
		}
		if len(tmp_t.Childs) >0 {
			childs = append(childs, tmp_t )
			tmp_t = t_c
			continue
		}
		if !inSlice(tmp_t.Rule, rules) {
			childs = append(childs, tmp_t )
			tmp_t = t_c
			continue
		}
		tmp_t = (merge_leaf(tmp_t, t_c))[0]
	}
	childs = append(childs, tmp_t )



	switch inSlice(target.Rule, rules) {

		case	true:
			t := append( []Target{ {[]Target{}, target.Rule, target.Value} }, childs...)
			t = merge_leaf( t... )
			if len(t) > 1 {
				return Target { childs, target.Rule, target.Value }
			}
			return t[0]

		default:
			return Target { childs, target.Rule, target.Value }

	}
}
