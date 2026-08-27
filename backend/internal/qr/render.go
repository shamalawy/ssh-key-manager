package qr

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
)

// PNG renders the symbol as a paletted PNG.
//
// A two-colour palette rather than RGBA keeps an enrolment code around two
// kilobytes, which matters because it is inlined into a JSON response: the
// alternative is a second endpoint that has to hold the pending secret in
// server state between two requests, and pending-secret state is exactly the
// kind of thing that gets left behind after a failed enrolment.
//
// moduleSize is the pixel width of one module and quiet is the margin in
// modules. Four is the specified minimum quiet zone; less than that and
// scanners struggle to find the symbol against a page.
func PNG(c *Code, moduleSize, quiet int) ([]byte, error) {
	if moduleSize < 1 {
		moduleSize = 1
	}
	if quiet < 0 {
		quiet = 0
	}

	side := (c.Size + quiet*2) * moduleSize
	img := image.NewPaletted(
		image.Rect(0, 0, side, side),
		color.Palette{color.White, color.Black},
	)

	for y := 0; y < side; y++ {
		my := y/moduleSize - quiet
		for x := 0; x < side; x++ {
			if c.At(x/moduleSize-quiet, my) {
				img.SetColorIndex(x, y, 1)
			}
		}
	}

	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DataURI encodes text as a QR code and returns it as a data: URI ready to put
// straight into an <img src>. Errors are the caller's to report; a missing
// image should degrade to the typed secret, never to a broken page.
func DataURI(text string, moduleSize int) (string, error) {
	code, err := Encode([]byte(text), LevelM)
	if err != nil {
		return "", err
	}
	raw, err := PNG(code, moduleSize, 4)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(raw), nil
}
