package azuretls

import (
	"strings"
)

// OrderedHeaders is a slice of headers.
type OrderedHeaders [][]string

type PHeader [4]string

type HeaderOrder []string

func (ph PHeader) GetDefault() {
	ph[0] = Method
	ph[1] = Authority
	ph[2] = Scheme
	ph[3] = Path
}

// Clone returns a copy of the header.
func (oh *OrderedHeaders) Clone() OrderedHeaders {
	var clone = make(OrderedHeaders, len(*oh))

	for i, header := range *oh {
		var fieldClone = make([]string, len(header))
		for j, field := range header {
			fieldClone[j] = field
		}
		clone[i] = fieldClone
	}

	return clone
}

// Add adds the value to the field.
// It appends to any existing values associated with the field.
func (oh *OrderedHeaders) Add(field string, value ...string) {
	for i, c := range *oh {
		if c[0] == field {
			(*oh)[i] = append((*oh)[i], value...)
		}
	}
}

// Set sets the field to the given value.
// It replaces any existing values associated with the field.
func (oh *OrderedHeaders) Set(field string, value ...string) {
	newList := append([]string{field}, value...)
	for i, c := range *oh {
		if c[0] == field {
			(*oh)[i] = newList
			return
		}
	}
	*oh = append(*oh, newList)
}

// Get returns the first value associated with the given field.
// If the field is not present, it returns an empty string.
func (oh *OrderedHeaders) Get(field string) string {
	for _, c := range *oh {
		if c[0] == field {
			return strings.Join(c[1:], "; ")
		}
	}

	return ""
}

// Remove removes the first instance of the field from the header.
// If the field is not present, it does nothing.
// Deprecated: Use Del instead.
func (oh *OrderedHeaders) Remove(field string) OrderedHeaders {
	return oh.Del(field)
}

// Del removes the first instance of the field from the header.
// If the field is not present, it does nothing.
func (oh *OrderedHeaders) Del(field string) OrderedHeaders {
	var index = -1
	for i := 0; i < len(*oh); i++ {
		if (*oh)[i][0] == field {
			index = i
		}
	}

	if index != -1 {
		return append((*oh)[:index], (*oh)[index+1:]...)
	}

	return *oh
}
