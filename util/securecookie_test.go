package util

import (
	"encoding/base64"
	"strings"
	"testing"
)

type secureCookiePayload struct {
	Sub  string `json:"sub"`
	Name string `json:"name"`
}

func TestSecureCookieRoundTrip(t *testing.T) {
	codec, err := NewSecureCookieCodec("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewSecureCookieCodec: %v", err)
	}
	want := secureCookiePayload{Sub: "user-1", Name: "alice"}
	encoded, err := codec.Encode(want)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got secureCookiePayload
	if err := codec.Decode(encoded, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != want {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

func TestSecureCookieTamperDetection(t *testing.T) {
	codec, err := NewSecureCookieCodec("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewSecureCookieCodec: %v", err)
	}
	encoded, err := codec.Encode(secureCookiePayload{Sub: "user-1", Name: "alice"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	tampered := []byte(encoded)
	// Flip a byte in the middle (ciphertext area) to invalidate the GCM tag.
	mid := len(tampered) / 2
	if tampered[mid] == 'A' {
		tampered[mid] = 'B'
	} else {
		tampered[mid] = 'A'
	}
	var got secureCookiePayload
	if err := codec.Decode(string(tampered), &got); err == nil {
		t.Fatal("expected tampered cookie to fail decoding")
	}
}

func TestSecureCookieWrongKeyRejected(t *testing.T) {
	encoder, err := NewSecureCookieCodec("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}
	decoder, err := NewSecureCookieCodec("fedcba9876543210fedcba9876543210")
	if err != nil {
		t.Fatalf("decoder: %v", err)
	}
	encoded, err := encoder.Encode(secureCookiePayload{Sub: "user-1", Name: "alice"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got secureCookiePayload
	if err := decoder.Decode(encoded, &got); err == nil {
		t.Fatal("expected a wrong-key decode to fail")
	}
}

func TestSecureCookieNonceIsRandom(t *testing.T) {
	codec, err := NewSecureCookieCodec("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewSecureCookieCodec: %v", err)
	}
	payload := secureCookiePayload{Sub: "user-1", Name: "alice"}
	first, err := codec.Encode(payload)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	second, err := codec.Encode(payload)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if first == second {
		t.Fatal("two encodings of the same payload must differ (random nonce)")
	}
}

func TestSecureCookieRejectsMalformed(t *testing.T) {
	codec, err := NewSecureCookieCodec("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewSecureCookieCodec: %v", err)
	}

	cases := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"not base64url", "!!!not base64!!!"},
		{"too short", "AAAA"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got secureCookiePayload
			if err := codec.Decode(tc.value, &got); err == nil {
				t.Fatalf("expected decode of %q to fail", tc.value)
			}
		})
	}

	// Truncating the tag must fail too.
	encoded, err := codec.Encode(secureCookiePayload{Sub: "user-1", Name: "alice"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got secureCookiePayload
	if err := codec.Decode(encoded[:len(encoded)-4], &got); err == nil {
		t.Fatal("expected a truncated cookie to fail decoding")
	}
	if err := codec.Decode(strings.Repeat("A", 200), &got); err == nil {
		t.Fatal("expected a bogus long cookie to fail decoding")
	}
}

func TestSecureCookieTypeMismatchRejected(t *testing.T) {
	codec, err := NewSecureCookieCodec("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewSecureCookieCodec: %v", err)
	}
	encoded, err := codec.Encode(secureCookiePayload{Sub: "user-1", Name: "alice"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// The GCM tag still verifies, but the plaintext does not match the target
	// type, so Decode must error rather than silently zero the fields.
	var got struct {
		Sub int `json:"sub"`
	}
	if err := codec.Decode(encoded, &got); err == nil {
		t.Fatal("expected a JSON type mismatch to fail decoding")
	}
}

// FuzzSecureCookieDecode feeds malformed and tampered cookie values to Decode.
// Malformed input must return an error rather than panic, and any input that
// does decode (a genuine token like the seed) must fail once its bytes are
// mutated, because the GCM tag covers the whole encoding.
func FuzzSecureCookieDecode(f *testing.F) {
	codec, err := NewSecureCookieCodec("0123456789abcdef0123456789abcdef")
	if err != nil {
		f.Fatalf("NewSecureCookieCodec: %v", err)
	}
	valid, err := codec.Encode(secureCookiePayload{Sub: "user-1", Name: "alice"})
	if err != nil {
		f.Fatalf("Encode: %v", err)
	}

	// Seed from the vectors the unit tests already exercise: the valid
	// encoding, the malformed forms and a truncated (tampered) one.
	f.Add(valid)
	f.Add("")
	f.Add("!!!not base64!!!")
	f.Add("AAAA")
	f.Add(strings.Repeat("A", 200))
	f.Add(valid[:len(valid)-4])

	f.Fuzz(func(t *testing.T, value string) {
		var got secureCookiePayload
		if err := codec.Decode(value, &got); err != nil {
			// Malformed or tampered input: rejection is the expected outcome.
			return
		}
		// The value is a genuine token (only the seed can produce one), so
		// flipping a bit anywhere in the encoding must now fail the tag.
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			t.Fatalf("Decode succeeded but base64 decoding failed: %v", err)
		}
		raw[len(raw)/2] ^= 0x01
		tampered := base64.RawURLEncoding.EncodeToString(raw)
		var tamperedPayload secureCookiePayload
		if err := codec.Decode(tampered, &tamperedPayload); err == nil {
			t.Fatalf("Decode of a tampered value (%q) succeeded, want an error", tampered)
		}
	})
}
