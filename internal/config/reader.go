package config

import "bytes"

func bytesReader(raw []byte) *bytes.Reader { return bytes.NewReader(raw) }
