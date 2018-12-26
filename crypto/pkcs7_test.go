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
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "No padding required",
			args: args{
				b: []byte("aaa"),
				bsize: 3,
			},
			want: []byte("aaa"),
			wantErr: false,
		},
		{
			name: "Data too large",
			args: args{
				b: []byte("aaa"),
				bsize: 2,
			},
			wantErr: true,
		},
		{
			name: "Normal padding",
			args: args{
				b: []byte("aa"),
				bsize: 4,
			},
			want: append([]byte("aa"), 0x02, 0x02),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PadPkcs7(tt.args.b, tt.args.bsize)
			if (err != nil) != tt.wantErr {
				t.Errorf("PadPkcs7() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PadPkcs7() = %v, want %v", got, tt.want)
			}
		})
	}
}
