package crypto

import (
	"reflect"
	"testing"
)

func TestPadPkcs7(t *testing.T) {
	type args struct {
		b     []byte
		bsize int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "No padding required",
			args: args{
				b:     []byte("aaaaaa"),
				bsize: 3,
			},
			want: []byte("aaaaaa"),
		},
		{
			name: "Single block padding",
			args: args{
				b:     []byte("aa"),
				bsize: 4,
			},
			want: append([]byte("aa"), 0x02, 0x02),
		},
		{
			name: "Multiple blocks padding",
			args: args{
				b:     []byte("aaa"),
				bsize: 2,
			},
			want: append([]byte("aaa"), 0x01),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PadPkcs7(tt.args.b, tt.args.bsize)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PadPkcs7() = %v, want %v", got, tt.want)
			}
		})
	}
}
