package gpg

// OpenPGP packet tags (RFC 4880 §4.3).
const (
	tagPKESK = 1 // public-key encrypted session key
	tagSKESK = 3 // symmetric-key (passphrase) encrypted session key
)

// WithoutPassphrasePackets returns msg without its passphrase packets
// (SKESK), keeping the public-key packets and the encrypted data byte for
// byte. Decrypting with a secret key then never asks for a passphrase:
// GnuPG 2.5 tries a message's passphrase packet before its key packets, so
// users would first be asked for the vault's unlock secret, which they do
// not know.
//
// Only the leading session-key packets are parsed; everything from the
// first other packet on is copied unchanged. Input that is not a binary
// OpenPGP message of that shape is returned as it is.
func WithoutPassphrasePackets(msg []byte) []byte {
	out := make([]byte, 0, len(msg))
	rest := msg
	for len(rest) > 0 {
		tag, n, ok := packetHeader(rest)
		if !ok {
			return msg
		}
		if tag != tagPKESK && tag != tagSKESK {
			return append(out, rest...) // the encrypted data and anything after it
		}
		if n > len(rest) {
			return msg
		}
		if tag == tagPKESK {
			out = append(out, rest[:n]...)
		}
		rest = rest[n:]
	}
	return msg // no encrypted data at all: not a message we understand
}

// packetHeader returns the tag of the packet at the start of b and its total
// size (header and body). Indeterminate and partial lengths, which only
// data packets may use, report ok=false unless the packet is not a
// session-key packet (the caller stops before needing its size).
func packetHeader(b []byte) (tag, size int, ok bool) {
	if len(b) < 2 || b[0]&0x80 == 0 {
		return 0, 0, false
	}
	if b[0]&0x40 == 0 { // old format
		tag = int(b[0]>>2) & 0x0f
		switch b[0] & 0x03 {
		case 0:
			return tag, 2 + int(b[1]), true
		case 1:
			if len(b) < 3 {
				return 0, 0, false
			}
			return tag, 3 + (int(b[1])<<8 | int(b[2])), true
		case 2:
			if len(b) < 5 {
				return 0, 0, false
			}
			return tag, 5 + (int(b[1])<<24 | int(b[2])<<16 | int(b[3])<<8 | int(b[4])), true
		default: // indeterminate length: only for data packets
			return tag, 0, tag != tagPKESK && tag != tagSKESK
		}
	}
	tag = int(b[0]) & 0x3f // new format
	switch l := int(b[1]); {
	case l < 192:
		return tag, 2 + l, true
	case l < 224:
		if len(b) < 3 {
			return 0, 0, false
		}
		return tag, 3 + ((l-192)<<8 + int(b[2]) + 192), true
	case l == 255:
		if len(b) < 6 {
			return 0, 0, false
		}
		return tag, 6 + (int(b[2])<<24 | int(b[3])<<16 | int(b[4])<<8 | int(b[5])), true
	default: // partial body length: only for data packets
		return tag, 0, tag != tagPKESK && tag != tagSKESK
	}
}
