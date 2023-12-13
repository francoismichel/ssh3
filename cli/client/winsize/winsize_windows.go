//go:build windows
package winsize

import "os"
import "golang.org/x/term"




func GetWinsize() (ws WindowSize, err error) {
	// for Windows, it is a bit more complicated to get the window size in pixels, so on rely
	// on window size expressed in columns
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return ws, err
	}
	ws.NCols = uint16(width)
	ws.NRows = uint16(height)
	ws.PixelWidth = 0
	ws.PixelHeight = 0
	return ws, nil
}