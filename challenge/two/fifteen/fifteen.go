package fifteen

import (
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/rs/zerolog/log"
)

type ch struct{}

func (c *ch) Solve() error {
	tests := []struct {
		padding     []byte
		expected    string
		expectedErr error
	}{
		{
			padding:     []byte{0x04, 0x04, 0x04, 0x04},
			expected:    "ICE ICE BABY",
			expectedErr: nil,
		},
		{
			padding:     []byte{0x05, 0x05, 0x05, 0x05},
			expectedErr: crypto.InvalidPaddingErr,
		},
		{
			padding:     []byte{0x01, 0x02, 0x03, 0x04},
			expectedErr: crypto.InvalidPaddingErr,
		},
	}
	for _, tt := range tests {
		pt := append([]byte("ICE ICE BABY"), tt.padding...)
		b, err := crypto.RemovePkcs7(pt, 16)
		if err != tt.expectedErr {
			log.Error().Msgf("Expected error %d does not match actual error %s", tt.expectedErr, err)
			continue
		}
		if string(b) != tt.expected {
			log.Error().Msgf("Expected result %s, but got %s", tt.expected, string(b))
		}
	}
	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
