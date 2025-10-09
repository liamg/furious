package scan

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTestIteration(t *testing.T) {
	ti := NewTargetIterator("192.168.1.1/24")

	ip, err := ti.Peek()
	require.Nil(t, err)

	assert.Equal(t, ip.String(), "192.168.1.0")

	for i := 0; i < 256; i++ {

		ip, err := ti.Peek()
		require.Nil(t, err)
		assert.Equal(t, ip.String(), fmt.Sprintf("192.168.1.%d", i))

		ip, err = ti.Next()
		require.Nil(t, err)
		assert.Equal(t, ip.String(), fmt.Sprintf("192.168.1.%d", i))
	}

}
