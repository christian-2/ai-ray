package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInt8ToString(t *testing.T) {
	assert.Equal(t, "123", int8ToString([]int8{'1', '2', '3'}))
}

func TestInt8ToStringNotANumber(t *testing.T) {
	assert.Equal(t, "ABC", int8ToString([]int8{'A', 'B', 'C'}))
}
