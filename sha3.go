package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Keccakの状態配列のサイズ (1600 bits = 5x5x64)
const B = 1600
const W = 64 // ワードサイズ
const L = 6  // log2(W)

// SHA3-256のレート(bits)とキャパシティ
const RATE = 1088
const CAPACITY = 512

// ラウンド定数
var RC = []uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
	0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// 回転オフセット
var r = [][]int{
	{0, 36, 3, 41, 18},
	{1, 44, 10, 45, 2},
	{62, 6, 43, 15, 61},
	{28, 55, 25, 21, 56},
	{27, 20, 39, 8, 14},
}

type state struct {
	a [5][5]uint64
}

// 左ローテーション
func rotl64(x uint64, y int) uint64 {
	return (x << uint(y)) | (x >> uint(64-y))
}

// θステップ
func (s *state) theta() {
	c := [5]uint64{}
	d := [5]uint64{}

	for x := 0; x < 5; x++ {
		c[x] = s.a[x][0] ^ s.a[x][1] ^ s.a[x][2] ^ s.a[x][3] ^ s.a[x][4]
	}

	for x := 0; x < 5; x++ {
		d[x] = c[(x+4)%5] ^ rotl64(c[(x+1)%5], 1)
		for y := 0; y < 5; y++ {
			s.a[x][y] ^= d[x]
		}
	}
}

// ρとπステップ
func (s *state) rhoPi() {
	temp := s.a[1][0]
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			current := s.a[x][y]
			s.a[x][y] = rotl64(temp, r[x][y])
			temp = current
		}
	}
}

// χステップ
func (s *state) chi() {
	b := [5][5]uint64{}
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			b[x][y] = s.a[x][y]
		}
	}

	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			s.a[x][y] = b[x][y] ^ ((^b[(x+1)%5][y]) & b[(x+2)%5][y])
		}
	}
}

// ιステップ
func (s *state) iota(round int) {
	s.a[0][0] ^= RC[round]
}

// Keccak-f[1600]置換
func (s *state) keccakF1600() {
	for i := 0; i < 24; i++ {
		s.theta()
		s.rhoPi()
		s.chi()
		s.iota(i)
	}
}

// パディング
func pad(message []byte, rate int) []byte {
	remaining := rate - (len(message)*8)%rate
	if remaining == 0 {
		remaining = rate
	}

	padLen := (remaining + 7) / 8
	padding := make([]byte, padLen)
	padding[0] = 0x06 // SHA-3のパディング
	padding[len(padding)-1] |= 0x80

	return append(message, padding...)
}

// SHA3-256のメイン関数
func sha3_256(message []byte) []byte {
	// 状態の初期化
	s := new(state)

	// パディング
	paddedMsg := pad(message, RATE)

	// メッセージブロックの処理
	for i := 0; i < len(paddedMsg); i += RATE / 8 {
		// ブロックとXOR
		for j := 0; j < RATE/8; j++ {
			if i+j < len(paddedMsg) {
				byteIndex := i + j
				wordIndex := j / 8
				bytePosition := j % 8
				s.a[wordIndex%5][wordIndex/5] ^= uint64(paddedMsg[byteIndex]) << uint(bytePosition*8)
			}
		}
		s.keccakF1600()
	}

	// 出力の生成（256ビット）
	output := make([]byte, 32)
	outIndex := 0
	wordIndex := 0

	for outIndex < 32 {
		word := s.a[wordIndex%5][wordIndex/5]
		for i := 0; i < 8 && outIndex < 32; i++ {
			output[outIndex] = byte(word >> uint(i*8))
			outIndex++
		}
		wordIndex++
	}

	return output
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("\nSHA3-256ハッシュ値を計算する文字列を入力してください (終了する場合は'q'を入力):\n> ")

		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("入力エラー:", err)
			continue
		}

		input = strings.TrimSpace(input)

		if input == "q" {
			fmt.Println("プログラムを終了します")
			break
		}

		// ハッシュ値を計算
		hash := sha3_256([]byte(input))

		// 16進数に変換して表示
		fmt.Printf("\n入力文字列: %s\n", input)
		fmt.Printf("SHA3-256ハッシュ値: ")
		for _, b := range hash {
			fmt.Printf("%02x", b)
		}
		fmt.Println()
	}
}
