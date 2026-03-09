package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/awnumar/memguard"
	"github.com/c0mm4nd/go-ripemd"
	"github.com/go-piv/piv-go/v2/piv"
	"github.com/martinlindhe/gogost/gost34112012256"
	"github.com/tjfoc/gmsm/sm3"
)

// Signature metadata structure
type SignatureMetadata struct {
	Author    string
	email     string
	URL       string
	Filename  string
	FileSize  int64
	Timestamp time.Time
}

// ecSignature represents an ECDSA signature with R and S components
type ecSignature struct{ R, S *big.Int }

// Supported algorithms
const (
	AlgorithmECCP256 = "ECCP256"
	AlgorithmECCP384 = "ECCP384"
	AlgorithmED25519 = "ED25519"
)

var supportedAlgorithms = map[string]bool{
	AlgorithmECCP256: true,
	AlgorithmECCP384: true,
	AlgorithmED25519: true,
}

// Mapping from elliptic curve to algorithm name
var curveToAlgorithm = map[elliptic.Curve]string{
	elliptic.P256(): AlgorithmECCP256,
	elliptic.P384(): AlgorithmECCP384,
}

// Mapping from elliptic curve to hash function
var curveToHash = map[elliptic.Curve]crypto.Hash{
	elliptic.P256(): crypto.SHA256,
	elliptic.P384(): crypto.SHA384,
}

// Ed25519 constants
const (
	Ed25519SignatureSize = 64
	Ed25519PublicKeySize = 32
	Ed25519CombinedSize  = Ed25519SignatureSize + Ed25519PublicKeySize
)

const (
	minRSABits = 2048
)

// Supported RSA key sizes
var supportedRSASizes = map[int]string{
	2048: "RSA2048",
	3072: "RSA3072",
	4096: "RSA4096",
}

// GUI structure with progress bar and file size display
type GUI struct {
	app            fyne.App
	window         fyne.Window
	themeToggle    *widget.Button
	pinEntry       *widget.Entry
	statusLabel    *widget.Label
	authorEntry    *widget.Entry
	emailEntry     *widget.Entry
	urlEntry       *widget.Entry
	filenameLabel  *widget.Label
	filesizeLabel  *widget.Label
	sigDisplay     *widget.Label
	progressBar    *widget.ProgressBar
	progressLabel  *widget.Label
	currentTheme   string
	encryptionUsed bool
	signingMode    bool
	currentFile    string
	signaturePath  string
	fileSelected   bool
}

func main() {
	defer memguard.Purge()
	
	// Set UTF-8 as default encoding
	os.Setenv("LANG", "en_US.UTF-8")
	os.Setenv("LC_ALL", "en_US.UTF-8")
	
	gui := &GUI{
		app:            app.NewWithID("oc2mx.net.yubisigner"),
		currentTheme:   "dark",
		encryptionUsed: false,
		signingMode:    true,
		currentFile:    "",
		signaturePath:  "",
		fileSelected:   false,
	}
	
	gui.window = gui.app.NewWindow("yubisigner")
	gui.window.Resize(fyne.NewSize(550, 420))
	gui.createUI()
	gui.applyTheme()
	gui.window.SetContent(gui.createMainUI())
	gui.window.CenterOnScreen()
	gui.window.ShowAndRun()
}

// createUI initializes all UI components
func (g *GUI) createUI() {
	// Author Entry
	g.authorEntry = widget.NewEntry()
	g.authorEntry.SetPlaceHolder("unknown")
	
	// email Entry
	g.emailEntry = widget.NewEntry()
	g.emailEntry.SetPlaceHolder("n/a")
	
	// URL Entry
	g.urlEntry = widget.NewEntry()
	g.urlEntry.SetPlaceHolder("n/a")

	// Filename Label (shows selected file)
	g.filenameLabel = widget.NewLabel("No file selected")
	g.filenameLabel.TextStyle = fyne.TextStyle{Italic: true}
	
	// Filesize Label (shows file size in bytes)
	g.filesizeLabel = widget.NewLabel("")
	g.filesizeLabel.TextStyle = fyne.TextStyle{Monospace: true}
	g.filesizeLabel.Hide()

	// PIN Entry
	g.pinEntry = widget.NewPasswordEntry()
	g.pinEntry.SetPlaceHolder("")
	g.pinEntry.Validator = func(s string) error {
		if len(s) > 8 {
			return fmt.Errorf("PIN must be max 8 characters")
		}
		for _, r := range s {
			if r > 127 {
				return fmt.Errorf("PIN must contain only ASCII characters")
			}
		}
		return nil
	}

	// Status Label
	g.statusLabel = widget.NewLabel("Ready")
	g.statusLabel.Wrapping = fyne.TextWrapWord

	// Signature Display (shows existing signature)
	g.sigDisplay = widget.NewLabel("")
	g.sigDisplay.TextStyle = fyne.TextStyle{Italic: true}

	// Progress bar for large files
	g.progressBar = widget.NewProgressBar()
	g.progressBar.Min = 0
	g.progressBar.Max = 1
	g.progressBar.Hide()
	
	// Progress percentage label
	g.progressLabel = widget.NewLabel("")
	g.progressLabel.Alignment = fyne.TextAlignCenter
	g.progressLabel.Hide()

	// Theme Toggle
	g.themeToggle = widget.NewButton("☀️", g.toggleTheme)
}

// createMainUI builds the main layout
func (g *GUI) createMainUI() fyne.CanvasObject {
	// Buttons
	signBtn := widget.NewButton("Sign", g.onSignClick)
	signBtn.Importance = widget.HighImportance
	
	verifyBtn := widget.NewButton("Verify", g.onVerifyClick)
	verifyBtn.Importance = widget.HighImportance
	
	selectFileBtn := widget.NewButton("Select File", g.onSelectFile)
	selectFileBtn.Importance = widget.MediumImportance

	// All three buttons centered
	buttonContainer := container.NewCenter(
		container.NewHBox(
			selectFileBtn,
			signBtn,
			verifyBtn,
		),
	)

	// Theme toggle at top right
	topRightContainer := container.NewHBox(
		layout.NewSpacer(),
		g.themeToggle,
	)

	// Metadata grid
	metadataGrid := container.New(layout.NewFormLayout(),
		widget.NewLabel("Author:"),
		g.authorEntry,
		widget.NewLabel("Email:"),
		g.emailEntry,
		widget.NewLabel("URL:"),
		g.urlEntry,
	)

	// File info container with filename and filesize
	fileInfoContainer := container.NewVBox(
		g.filenameLabel,
		g.filesizeLabel,
	)

	// Clear Button
	clearBtn := widget.NewButton("Clear", g.onClear)
	clearBtn.Importance = widget.HighImportance

	// PIN Container
	pinContainer := container.NewHBox(
		layout.NewSpacer(),
		widget.NewLabel("PIN:"),
		g.pinEntry,
		clearBtn,
		layout.NewSpacer(),
	)

	// Progress Container
	progressContainer := container.NewVBox(
		g.progressLabel,
		g.progressBar,
	)

	// Main container
	topContainer := container.NewVBox(
		topRightContainer,
		widget.NewSeparator(),
		buttonContainer,
		widget.NewSeparator(),
		metadataGrid,
		fileInfoContainer,
		widget.NewSeparator(),
		g.sigDisplay,
		progressContainer,
	)

	bottomContainer := container.NewVBox(
		widget.NewSeparator(),
		pinContainer,
		g.statusLabel,
	)

	mainContainer := container.NewBorder(
		topContainer,
		bottomContainer,
		nil,
		nil,
	)
	
	return mainContainer
}

// toggleTheme switches between light and dark theme
func (g *GUI) toggleTheme() {
	if g.currentTheme == "dark" {
		g.app.Settings().SetTheme(theme.LightTheme())
		g.currentTheme = "light"
		g.themeToggle.SetText("🌙")
	} else {
		g.app.Settings().SetTheme(theme.DarkTheme())
		g.currentTheme = "dark"
		g.themeToggle.SetText("☀️")
	}
}

// applyTheme sets the initial theme
func (g *GUI) applyTheme() {
	if g.currentTheme == "dark" {
		g.app.Settings().SetTheme(theme.DarkTheme())
		g.themeToggle.SetText("☀️")
	} else {
		g.app.Settings().SetTheme(theme.LightTheme())
		g.themeToggle.SetText("🌙")
	}
}

// selectFile opens file dialog (modal)
func (g *GUI) selectFile(callback func()) {
	dialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil {
			g.statusLabel.SetText("Error selecting file: " + err.Error())
			return
		}
		if reader == nil {
			return
		}
		defer reader.Close()
		
		g.currentFile = reader.URI().Path()
		g.filenameLabel.SetText(filepath.Base(g.currentFile))
		g.signaturePath = g.currentFile + ".sig"
		g.fileSelected = true
		
		fileInfo, err := os.Stat(g.currentFile)
		if err != nil {
			g.statusLabel.SetText("Error getting file info: " + err.Error())
			return
		}
		
		// Show file size in bytes and human readable format
		fileSize := fileInfo.Size()
		g.filesizeLabel.SetText(fmt.Sprintf("Size: %d bytes (%s)", 
			fileSize, formatByteSize(int(fileSize))))
		g.filesizeLabel.Show()
		
		g.statusLabel.SetText(fmt.Sprintf("Selected: %s", filepath.Base(g.currentFile)))
		
		// Check if signature exists
		if _, err := os.Stat(g.signaturePath); err == nil {
			g.sigDisplay.SetText("✓ " + filepath.Base(g.signaturePath))
		} else {
			g.sigDisplay.SetText("")
		}
		
		// Callback after file selection
		if callback != nil {
			callback()
		}
	}, g.window)
	
	// Make modal (stays in foreground)
	dialog.Show()
}

// onSelectFile - just select file
func (g *GUI) onSelectFile() {
	g.selectFile(func() {
		g.statusLabel.SetText("File selected. Click Sign to sign or Verify to verify.")
	})
}

// showPinDialog shows a modal PIN dialog
func (g *GUI) showPinDialog(message string, callback func(string)) {
	pinEntry := widget.NewPasswordEntry()
	pinEntry.SetPlaceHolder("Enter PIN")
	
	d := dialog.NewCustomConfirm(
		"PIN Required",
		"OK",
		"Cancel",
		container.NewVBox(
			widget.NewLabel(message),
			pinEntry,
		),
		func(confirmed bool) {
			if confirmed && pinEntry.Text != "" {
				callback(pinEntry.Text)
			}
		},
		g.window,
	)
	d.Show()
}

// normalizeToCRLF converts any line ending to RFC-compliant CRLF
func normalizeToCRLF(data []byte) []byte {
	s := string(data)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\n", "\r\n")
	return []byte(s)
}

// ensureUTF8 ensures the string is valid UTF-8
func ensureUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, " ")
}

// onSignClick - hybrid approach with progress feedback
func (g *GUI) onSignClick() {
	g.signingMode = true
	
	if g.currentFile == "" {
		g.statusLabel.SetText("Error: No file selected")
		return
	}
	
	if g.pinEntry.Text == "" {
		g.showPinDialog("PIN required for signing", func(pin string) {
			g.pinEntry.SetText(pin)
			g.onSignClick()
		})
		return
	}

	// Get file info
	fileInfo, err := os.Stat(g.currentFile)
	if err != nil {
		g.statusLabel.SetText("Error getting file info: " + err.Error())
		return
	}

	fileSize := fileInfo.Size()
	
	// Ensure filesize label is visible
	if g.filesizeLabel.Text == "" {
		g.filesizeLabel.SetText(fmt.Sprintf("Size: %d bytes (%s)", 
			fileSize, formatByteSize(int(fileSize))))
		g.filesizeLabel.Show()
	}
	
	// Show initial feedback with file size
	g.statusLabel.SetText(fmt.Sprintf("Preparing to sign %s (%s)...", 
		filepath.Base(g.currentFile), formatByteSize(int(fileSize))))
	
	// Decide strategy based on file size
	if fileSize <= 1024*1024*1024 { // <= 1GB - load into RAM
		// Show progress for RAM loading
		g.progressBar.SetValue(0)
		g.progressBar.Show()
		g.progressLabel.SetText("Loading file...")
		g.progressLabel.Show()
		g.statusLabel.SetText(fmt.Sprintf("Loading %s into RAM...", filepath.Base(g.currentFile)))
		
		// Use goroutine to keep UI responsive
		go func() {
			startTime := time.Now()
			
			// Read entire file into RAM with progress simulation
			file, err := os.Open(g.currentFile)
			if err != nil {
				g.showErrorAsync("Error opening file: " + err.Error())
				return
			}
			
			// Read file in chunks to show progress even in RAM mode
			var data []byte
			buf := make([]byte, 32*1024*1024) // 32MB chunks
			bytesRead := int64(0)
			
			for {
				n, err := file.Read(buf)
				if n > 0 {
					data = append(data, buf[:n]...)
					bytesRead += int64(n)
					
					// Update progress
					progress := float64(bytesRead) / float64(fileSize)
					fyne.Do(func() {
						g.progressBar.SetValue(progress)
						elapsed := time.Since(startTime).Seconds()
						speed := float64(bytesRead) / elapsed / 1024 / 1024
						g.progressLabel.SetText(fmt.Sprintf("Loading: %d%% (%.1f MB/s)", 
							int(progress*100), speed))
					})
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					g.showErrorAsync("Error reading file: " + err.Error())
					return
				}
			}
			file.Close()
			
			// Calculate hashes in RAM
			fyne.Do(func() {
				g.progressLabel.SetText("Calculating hashes...")
			})
			
			hashes := g.calculateHashesRAM(data)
			
			// Prepare metadata
			author := g.authorEntry.Text
			if author == "" {
				author = "unknown"
			} else {
				author = ensureUTF8(author)
			}
			
			email := g.emailEntry.Text
			if email == "" {
				email = "n/a"
			}
			
			url := g.urlEntry.Text
			if url == "" {
				url = "n/a"
			}

			// Build metadata section with file size
			metadata := fmt.Sprintf("Author: %s\r\n", author)
			metadata += fmt.Sprintf("Signed at: %s\r\n", time.Now().UTC().Format("2006-01-02 15:04:05 +0000"))
			metadata += fmt.Sprintf("Filename: %s\r\n", filepath.Base(g.currentFile))
			metadata += fmt.Sprintf("File size: %d bytes\r\n", fileSize)
			metadata += fmt.Sprintf("Email: %s\r\n", email)
			metadata += fmt.Sprintf("URL: %s\r\n", url)
			metadata += g.formatHashes(hashes)

			// Sign metadata
			fyne.Do(func() {
				g.progressLabel.SetText("Signing metadata...")
			})
			
			sig, algo, err := g.signDataInternal([]byte(g.pinEntry.Text), []byte(metadata))
			if err != nil {
				g.showErrorAsync("Signing failed: " + err.Error())
				return
			}

			// Build final signature
			result := metadata
			result += "-----BEGIN YUBISIGNER " + algo + " SIGNATURE-----\r\n"
			result += formatSignatureRFC(sig)
			result += "-----END YUBISIGNER " + algo + " SIGNATURE-----\r\n"

			// Write signature to file
			sigFile := g.currentFile + ".sig"
			err = os.WriteFile(sigFile, []byte(result), 0644)
			if err != nil {
				g.showErrorAsync("Error writing signature: " + err.Error())
				return
			}
			
			fyne.Do(func() {
				g.signaturePath = sigFile
				g.sigDisplay.SetText("✓ " + filepath.Base(sigFile))
				g.progressBar.Hide()
				g.progressLabel.Hide()
				totalTime := time.Since(startTime).Seconds()
				g.statusLabel.SetText(fmt.Sprintf("✓ File signed successfully in %.1f seconds: %s", 
					totalTime, filepath.Base(sigFile)))
			})
		}()
		
	} else { // > 1GB - use optimized chunking with progress
		g.progressBar.SetValue(0)
		g.progressBar.Show()
		g.progressLabel.SetText("0%")
		g.progressLabel.Show()
		g.statusLabel.SetText(fmt.Sprintf("Processing large file (%s)...", formatByteSize(int(fileSize))))

		// Start async processing with optimized chunking
		go func() {
			startTime := time.Now()
			
			hashes, err := g.calculateFileHashesOptimized(g.currentFile)
			if err != nil {
				g.showErrorAsync("Error reading file: " + err.Error())
				return
			}

			// Prepare metadata
			author := g.authorEntry.Text
			if author == "" {
				author = "unknown"
			} else {
				author = ensureUTF8(author)
			}
			
			email := g.emailEntry.Text
			if email == "" {
				email = "n/a"
			}
			
			url := g.urlEntry.Text
			if url == "" {
				url = "n/a"
			}

			// Build metadata section with file size
			metadata := fmt.Sprintf("Author: %s\r\n", author)
			metadata += fmt.Sprintf("Signed at: %s\r\n", time.Now().UTC().Format("2006-01-02 15:04:05 +0000"))
			metadata += fmt.Sprintf("Filename: %s\r\n", filepath.Base(g.currentFile))
			metadata += fmt.Sprintf("File size: %d bytes\r\n", fileSize)
			metadata += fmt.Sprintf("Email: %s\r\n", email)
			metadata += fmt.Sprintf("URL: %s\r\n", url)
			metadata += g.formatHashes(hashes)

			// Sign metadata
			g.updateStatusAsync("Signing metadata...")
			sig, algo, err := g.signDataInternal([]byte(g.pinEntry.Text), []byte(metadata))
			if err != nil {
				g.showErrorAsync("Signing failed: " + err.Error())
				return
			}

			// Build final signature
			result := metadata
			result += "-----BEGIN YUBISIGNER " + algo + " SIGNATURE-----\r\n"
			result += formatSignatureRFC(sig)
			result += "-----END YUBISIGNER " + algo + " SIGNATURE-----\r\n"

			// Write signature to file
			sigFile := g.currentFile + ".sig"
			err = os.WriteFile(sigFile, []byte(result), 0644)
			if err != nil {
				g.showErrorAsync("Error writing signature: " + err.Error())
				return
			}
			
			fyne.Do(func() {
				g.signaturePath = sigFile
				g.sigDisplay.SetText("✓ " + filepath.Base(sigFile))
				g.progressBar.Hide()
				g.progressLabel.Hide()
				totalTime := time.Since(startTime).Seconds()
				g.statusLabel.SetText(fmt.Sprintf("✓ File signed successfully in %.1f seconds: %s", 
					totalTime, filepath.Base(sigFile)))
			})
		}()
	}
}

// onVerifyClick - verify with hybrid approach and proper synchronization
func (g *GUI) onVerifyClick() {
	g.signingMode = false
	
	if g.currentFile == "" {
		g.statusLabel.SetText("Error: No file selected")
		return
	}

	// Try to find corresponding .sig file
	sigFile := g.currentFile + ".sig"
	sigData, err := os.ReadFile(sigFile)
	if err != nil {
		g.showErrorPopup("Signature not valid", nil)
		return
	}

	// Parse signature file
	s := string(sigData)
	
	// Find BEGIN line
	beginPattern := regexp.MustCompile(`-----BEGIN YUBISIGNER ([A-Z0-9]+) SIGNATURE-----`)
	beginMatch := beginPattern.FindStringSubmatch(s)
	if beginMatch == nil {
		g.showErrorPopup("Signature not valid", nil)
		return
	}
	
	algorithm := beginMatch[1]
	beginLine := beginMatch[0]
	endLine := "-----END YUBISIGNER " + algorithm + " SIGNATURE-----"
	
	// Find positions
	beginIdx := strings.Index(s, beginLine)
	endIdx := strings.Index(s, endLine)
	
	if beginIdx == -1 || endIdx == -1 || endIdx <= beginIdx {
		g.showErrorPopup("Signature not valid", nil)
		return
	}
	
	// Extract metadata (everything before BEGIN)
	metadataStr := strings.TrimSpace(s[:beginIdx])
	
	// Extract signature hex (between BEGIN and END)
	sigBlock := s[beginIdx+len(beginLine) : endIdx]
	sigBlock = strings.TrimSpace(sigBlock)
	
	// Combine all hex lines
	re := regexp.MustCompile(`[^a-fA-F0-9]`)
	sigHex := re.ReplaceAllString(sigBlock, "")

	// Get current file info
	fileInfo, err := os.Stat(g.currentFile)
	if err != nil {
		g.statusLabel.SetText("Error getting file info: " + err.Error())
		return
	}

	currentFileSize := fileInfo.Size()
	
	// Extract expected file size from metadata
	metadataLines := strings.Split(metadataStr, "\r\n")
	expectedSize := int64(-1)
	for _, line := range metadataLines {
		if strings.HasPrefix(line, "File Size:") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &expectedSize)
			}
			break
		}
	}
	
	// Check file size mismatch
	if expectedSize != -1 && expectedSize != currentFileSize {
		g.showErrorPopup("Signature not valid", nil)
		return
	}
	
	// Create a channel for synchronization
	done := make(chan bool)
	
	// Show initial feedback
	g.statusLabel.SetText(fmt.Sprintf("Preparing to verify %s...", formatByteSize(int(currentFileSize))))
	
	// Decide strategy based on file size
	if currentFileSize <= 1024*1024*1024 { // <= 1GB - load into RAM
		// Show progress for RAM loading
		g.progressBar.SetValue(0)
		g.progressBar.Show()
		g.progressLabel.SetText("Loading file...")
		g.progressLabel.Show()
		g.statusLabel.SetText(fmt.Sprintf("Loading %s into RAM...", filepath.Base(g.currentFile)))
		
		go func() {
			defer func() { done <- true }()
			
			startTime := time.Now()
			
			// Read entire file into RAM with progress
			file, err := os.Open(g.currentFile)
			if err != nil {
				g.showErrorAsync("Signature not valid")
				return
			}
			
			var data []byte
			buf := make([]byte, 32*1024*1024) // 32MB chunks
			bytesRead := int64(0)
			
			for {
				n, err := file.Read(buf)
				if n > 0 {
					data = append(data, buf[:n]...)
					bytesRead += int64(n)
					
					// Update progress
					progress := float64(bytesRead) / float64(currentFileSize)
					fyne.Do(func() {
						g.progressBar.SetValue(progress)
						elapsed := time.Since(startTime).Seconds()
						speed := float64(bytesRead) / elapsed / 1024 / 1024
						g.progressLabel.SetText(fmt.Sprintf("Loading: %d%% (%.1f MB/s)", 
							int(progress*100), speed))
					})
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					g.showErrorAsync("Signature not valid")
					return
				}
			}
			file.Close()
			
			// Calculate hashes
			fyne.Do(func() {
				g.progressLabel.SetText("Calculating hashes...")
			})
			
			expectedHashes := g.calculateHashesRAM(data)
			expectedLines := strings.Split(g.formatHashes(expectedHashes), "\r\n")
			metadataLines := strings.Split(metadataStr, "\r\n")
			
			// Check each expected hash
			hashValid := true
			
			for _, expectedLine := range expectedLines {
				if expectedLine == "" {
					continue
				}
				expectedParts := strings.SplitN(expectedLine, ": ", 2)
				if len(expectedParts) != 2 {
					continue
				}
				hashName := strings.TrimSpace(expectedParts[0])
				hashValue := expectedParts[1]
				
				// Look for this hash in metadata
				found := false
				for _, metaLine := range metadataLines {
					if strings.Contains(metaLine, hashName+":") {
						metaParts := strings.SplitN(metaLine, ": ", 2)
						if len(metaParts) == 2 {
							metaValue := strings.TrimSpace(metaParts[1])
							if metaValue == hashValue {
								found = true
								break
							}
						}
					}
				}
				if !found {
					hashValid = false
					break
				}
			}
			
			if !hashValid {
				g.showErrorAsync("Signature not valid")
				return
			}

			// Verify signature
			fyne.Do(func() {
				g.progressLabel.SetText("Verifying signature...")
			})
			
			combined, err := hex.DecodeString(sigHex)
			if err != nil {
				g.showErrorAsync("Signature not valid")
				return
			}

			var verifyErr error
			
			switch algorithm {
			case AlgorithmED25519:
				hash := sha256.Sum256([]byte(metadataStr + "\r\n"))
				verifyErr = g.verifyEd25519(hash[:], combined)
			case AlgorithmECCP256, AlgorithmECCP384:
				verifyErr = g.verifyECDSA([]byte(metadataStr), combined, algorithm)
			default:
				g.showErrorAsync("Signature not valid")
				return
			}

			if verifyErr != nil {
				g.showErrorAsync("Signature not valid")
				return
			}

			// Show success with identicon
			publicKeyBytes, _ := extractPublicKeyFromSignature(combined, algorithm)
			
			displayBytes, err := extractPublicKeyDisplayBytes(publicKeyBytes, algorithm)
			if err != nil {
				displayBytes = publicKeyBytes
			}
			
			hexString := hex.EncodeToString(displayBytes)
			hashForIdenticon := sha256.Sum256([]byte(hexString))
			
			fyne.Do(func() {
				g.progressBar.Hide()
				g.progressLabel.Hide()
				totalTime := time.Since(startTime).Seconds()
				g.statusLabel.SetText(fmt.Sprintf("✓ File verified successfully in %.1f seconds", totalTime))
				g.showSuccessPopupWithIdenticon(hashForIdenticon[:])
			})
		}()
		
	} else { // > 1GB - use optimized chunking
		g.progressBar.SetValue(0)
		g.progressBar.Show()
		g.progressLabel.SetText("0%")
		g.progressLabel.Show()
		g.statusLabel.SetText(fmt.Sprintf("Verifying large file (%s)...", formatByteSize(int(currentFileSize))))

		go func() {
			defer func() { done <- true }()
			
			startTime := time.Now()
			
			expectedHashes, err := g.calculateFileHashesOptimized(g.currentFile)
			if err != nil {
				g.showErrorAsync("Signature not valid")
				return
			}
			
			expectedLines := strings.Split(g.formatHashes(expectedHashes), "\r\n")
			metadataLines := strings.Split(metadataStr, "\r\n")
			
			// Check each expected hash
			hashValid := true
			
			for _, expectedLine := range expectedLines {
				if expectedLine == "" {
					continue
				}
				expectedParts := strings.SplitN(expectedLine, ": ", 2)
				if len(expectedParts) != 2 {
					continue
				}
				hashName := strings.TrimSpace(expectedParts[0])
				hashValue := expectedParts[1]
				
				// Look for this hash in metadata
				found := false
				for _, metaLine := range metadataLines {
					if strings.Contains(metaLine, hashName+":") {
						metaParts := strings.SplitN(metaLine, ": ", 2)
						if len(metaParts) == 2 {
							metaValue := strings.TrimSpace(metaParts[1])
							if metaValue == hashValue {
								found = true
								break
							}
						}
					}
				}
				if !found {
					hashValid = false
					break
				}
			}
			
			if !hashValid {
				g.showErrorAsync("Signature not valid")
				return
			}

			// Verify signature
			g.updateStatusAsync("Verifying signature...")
			
			combined, err := hex.DecodeString(sigHex)
			if err != nil {
				g.showErrorAsync("Signature not valid")
				return
			}

			var verifyErr error
			
			switch algorithm {
			case AlgorithmED25519:
				hash := sha256.Sum256([]byte(metadataStr + "\r\n"))
				verifyErr = g.verifyEd25519(hash[:], combined)
			case AlgorithmECCP256, AlgorithmECCP384:
				verifyErr = g.verifyECDSA([]byte(metadataStr), combined, algorithm)
			default:
				g.showErrorAsync("Signature not valid")
				return
			}

			if verifyErr != nil {
				g.showErrorAsync("Signature not valid")
				return
			}

			// Show success with identicon
			publicKeyBytes, _ := extractPublicKeyFromSignature(combined, algorithm)
			
			displayBytes, err := extractPublicKeyDisplayBytes(publicKeyBytes, algorithm)
			if err != nil {
				displayBytes = publicKeyBytes
			}
			
			hexString := hex.EncodeToString(displayBytes)
			hashForIdenticon := sha256.Sum256([]byte(hexString))
			
			fyne.Do(func() {
				g.progressBar.Hide()
				g.progressLabel.Hide()
				totalTime := time.Since(startTime).Seconds()
				g.statusLabel.SetText(fmt.Sprintf("✓ File verified successfully in %.1f seconds", totalTime))
				g.showSuccessPopupWithIdenticon(hashForIdenticon[:])
			})
		}()
	}
	
	// Wait for goroutine to finish in background (non-blocking)
	go func() {
		<-done
	}()
}

// showErrorPopup shows simple error popup
func (g *GUI) showErrorPopup(message string, publicKeyBytes []byte) {
	// Ensure progress bars are hidden
	fyne.Do(func() {
		g.progressBar.Hide()
		g.progressLabel.Hide()
	})
	
	errorLabel := widget.NewLabel(message)
	errorLabel.Alignment = fyne.TextAlignCenter
	errorLabel.TextStyle = fyne.TextStyle{Bold: true}
	
	content := container.NewVBox(
		container.NewCenter(errorLabel),
	)
	
	d := dialog.NewCustom("Verification Failed", "OK", content, g.window)
	
	// Reset status after dialog closes
	d.SetOnClosed(func() {
		fyne.Do(func() {
			g.statusLabel.SetText("Ready")
		})
	})
	
	d.Show()
}

// showSuccessPopupWithIdenticon shows the identicon (modal)
func (g *GUI) showSuccessPopupWithIdenticon(hash []byte) {
	// Ensure progress bars are hidden
	fyne.Do(func() {
		g.progressBar.Hide()
		g.progressLabel.Hide()
	})
	
	identicon := NewClassicIdenticon(hash)
	img := identicon.Generate()
	fyneImg := canvas.NewImageFromImage(img)
	fyneImg.FillMode = canvas.ImageFillContain
	fyneImg.SetMinSize(fyne.NewSize(128, 128))

	successLabel := widget.NewLabel("Signature is valid")
	successLabel.Alignment = fyne.TextAlignCenter

	content := container.NewVBox(
		container.NewCenter(fyneImg),
		container.NewCenter(successLabel),
	)

	d := dialog.NewCustom("Verification Successful", "OK", content, g.window)
	
	// Reset status after dialog closes
	d.SetOnClosed(func() {
		fyne.Do(func() {
			g.statusLabel.SetText("Ready")
		})
	})
	
	d.Show()
}

// calculateHashesRAM - fastest method for files that fit in RAM
func (g *GUI) calculateHashesRAM(data []byte) map[string]string {
	hashes := make(map[string]string)
	
	// Streebog-256
	gostHasher := gost34112012256.New()
	gostHasher.Write(data)
	hashes["Streebog-256"] = hex.EncodeToString(gostHasher.Sum(nil))
	
	// RIPEMD-256
	ripemdHasher := ripemd.New256()
	ripemdHasher.Write(data)
	hashes["RIPEMD-256"] = hex.EncodeToString(ripemdHasher.Sum(nil))
	
	// SHA-256
	sha256Hash := sha256.Sum256(data)
	hashes["SHA-256"] = hex.EncodeToString(sha256Hash[:])
	
	// SM3
	sm3Hasher := sm3.New()
	sm3Hasher.Write(data)
	hashes["SM3"] = hex.EncodeToString(sm3Hasher.Sum(nil))
	
	return hashes
}

// calculateFileHashesOptimized - optimized for very large files with speed display
func (g *GUI) calculateFileHashesOptimized(filePath string) (map[string]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Get file size for progress calculation
	fileInfo, _ := os.Stat(filePath)
	totalSize := fileInfo.Size()
	
	// Dynamic buffer size based on file size
	bufSize := 32 * 1024 * 1024 // Default 32MB
	
	// For very large files, use larger buffer
	if totalSize > 4*1024*1024*1024 { // > 4GB
		bufSize = 64 * 1024 * 1024 // 64MB buffer
	}
	
	buf := make([]byte, bufSize)
	
	// Initialize hashers
	gostHasher := gost34112012256.New()
	ripemdHasher := ripemd.New256()
	sha256Hasher := sha256.New()
	sm3Hasher := sm3.New()

	bytesProcessed := int64(0)
	lastProgress := 0
	startTime := time.Now()
	
	for {
		n, err := file.Read(buf)
		if n > 0 {
			// Write to all hashers
			gostHasher.Write(buf[:n])
			ripemdHasher.Write(buf[:n])
			sha256Hasher.Write(buf[:n])
			sm3Hasher.Write(buf[:n])
			
			bytesProcessed += int64(n)
			
			// Update progress every 1% for better feedback
			progress := int(float64(bytesProcessed) / float64(totalSize) * 100)
			if progress > lastProgress {
				lastProgress = progress
				
				// Calculate speed in MB/s
				elapsed := time.Since(startTime).Seconds()
				speed := float64(bytesProcessed) / elapsed / 1024 / 1024
				
				// Calculate estimated time remaining
				var remainingStr string
				if progress > 0 && speed > 0 {
					remainingBytes := float64(totalSize - bytesProcessed)
					remainingTime := remainingBytes / (speed * 1024 * 1024)
					
					if remainingTime > 60 {
						remainingStr = fmt.Sprintf("%.1f min", remainingTime/60)
					} else {
						remainingStr = fmt.Sprintf("%.0f sec", remainingTime)
					}
				}
				
				fyne.Do(func() {
					g.progressBar.SetValue(float64(bytesProcessed) / float64(totalSize))
					
					if remainingStr != "" {
						g.progressLabel.SetText(fmt.Sprintf("%d%% (%.1f MB/s, %s)", 
							progress, speed, remainingStr))
					} else {
						g.progressLabel.SetText(fmt.Sprintf("%d%% (%.1f MB/s)", progress, speed))
					}
					
					// Also update status with size info
					if progress%10 == 0 { // Every 10%
						g.statusLabel.SetText(fmt.Sprintf("Processing: %s/%s", 
							formatByteSize(int(bytesProcessed)), 
							formatByteSize(int(totalSize))))
					}
				})
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	// Collect hashes
	hashes := make(map[string]string)
	hashes["Streebog-256"] = hex.EncodeToString(gostHasher.Sum(nil))
	hashes["RIPEMD-256"] = hex.EncodeToString(ripemdHasher.Sum(nil))
	hashes["SHA-256"] = hex.EncodeToString(sha256Hasher.Sum(nil))
	hashes["SM3"] = hex.EncodeToString(sm3Hasher.Sum(nil))
	
	return hashes, nil
}

// updateStatusAsync updates status label from async goroutine
func (g *GUI) updateStatusAsync(message string) {
	fyne.Do(func() {
		g.statusLabel.SetText(message)
	})
}

// showErrorAsync shows error asynchronously
func (g *GUI) showErrorAsync(message string) {
	fyne.Do(func() {
		g.progressBar.Hide()
		g.progressLabel.Hide()
		g.showErrorPopup(message, nil)
	})
}

// formatHashes formats hashes with right-aligned names
func (g *GUI) formatHashes(hashes map[string]string) string {
	// Sort keys alphabetically
	keys := make([]string, 0, len(hashes))
	for k := range hashes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	
	// Find longest key name for alignment
	maxLen := 0
	for _, k := range keys {
		if len(k) > maxLen {
			maxLen = len(k)
		}
	}
	
	// Build result string
	var result strings.Builder
	for _, k := range keys {
		paddedKey := fmt.Sprintf("%*s", maxLen, k)
		result.WriteString(fmt.Sprintf("%s: %s\r\n", paddedKey, hashes[k]))
	}
	
	return result.String()
}

// signDataInternal performs the actual signing operation
func (g *GUI) signDataInternal(pin, data []byte) (string, string, error) {
	yk, err := openYubiKey(0)
	if err != nil {
		return "", "", err
	}
	defer yk.Close()

	cert, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return "", "", fmt.Errorf("failed to get certificate from signature slot: %v", err)
	}

	// Handle Ed25519 signing
	if ed25519PubKey, ok := cert.PublicKey.(ed25519.PublicKey); ok {
		hash := sha256.Sum256(data)
		return g.signEd25519Data(string(pin), hash[:], ed25519PubKey, yk)
	}

	// Handle ECDSA signing
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("public key is not ECDSA or Ed25519")
	}

	algorithm, exists := curveToAlgorithm[pubKey.Curve]
	if !exists {
		return "", "", fmt.Errorf("unsupported curve: %v", pubKey.Curve)
	}

	hashFunc := curveToHash[pubKey.Curve]
	
	var digest []byte
	switch hashFunc {
	case crypto.SHA256:
		h := sha256.New()
		h.Write(data)
		digest = h.Sum(nil)
	case crypto.SHA384:
		h := sha512.New384()
		h.Write(data)
		digest = h.Sum(nil)
	default:
		return "", "", fmt.Errorf("unsupported hash algorithm for curve")
	}

	auth := piv.KeyAuth{PIN: string(pin)}
	priv, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, auth)
	if err != nil {
		return "", "", fmt.Errorf("failed to get private key: %v", err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return "", "", fmt.Errorf("key does not implement crypto.Signer")
	}

	asn1sig, err := signer.Sign(rand.Reader, digest, nil)
	if err != nil {
		return "", "", fmt.Errorf("signing failed: %v", err)
	}

	var sig ecSignature
	if _, err := asn1.Unmarshal(asn1sig, &sig); err != nil {
		return "", "", fmt.Errorf("ASN.1 unmarshal failed: %v", err)
	}

	curveSize := (pubKey.Curve.Params().BitSize + 7) / 8
	
	var raw []byte
	raw = append(raw, safePad(pubKey.X.Bytes(), curveSize)...)
	raw = append(raw, safePad(pubKey.Y.Bytes(), curveSize)...)
	raw = append(raw, safePad(sig.R.Bytes(), curveSize)...)
	raw = append(raw, safePad(sig.S.Bytes(), curveSize)...)
	
	return hex.EncodeToString(raw), algorithm, nil
}

// signEd25519Data handles Ed25519 signing
func (g *GUI) signEd25519Data(pin string, hash []byte, pubKey ed25519.PublicKey, yk *piv.YubiKey) (string, string, error) {
	auth := piv.KeyAuth{PIN: pin}
	priv, err := yk.PrivateKey(piv.SlotSignature, pubKey, auth)
	if err != nil {
		return "", "", fmt.Errorf("failed to get private key: %v", err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return "", "", fmt.Errorf("key does not implement crypto.Signer")
	}

	signature, err := signer.Sign(rand.Reader, hash, crypto.Hash(0))
	if err != nil {
		return "", "", fmt.Errorf("Ed25519 signing failed: %v", err)
	}

	combined := append(pubKey, signature...)
	return hex.EncodeToString(combined), AlgorithmED25519, nil
}

// verifyEd25519 verifies an Ed25519 signature
func (g *GUI) verifyEd25519(dataHash, combined []byte) error {
	if len(combined) != Ed25519CombinedSize {
		return fmt.Errorf("invalid Ed25519 signature block")
	}
	publicKey := combined[:Ed25519PublicKeySize]
	signature := combined[Ed25519PublicKeySize:]
	
	if !ed25519.Verify(ed25519.PublicKey(publicKey), dataHash, signature) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}
	return nil
}

// verifyECDSA verifies an ECDSA signature
func (g *GUI) verifyECDSA(data, combined []byte, algorithm string) error {
	var curve elliptic.Curve
	var hashFunc crypto.Hash
	
	switch algorithm {
	case AlgorithmECCP256:
		curve = elliptic.P256()
		hashFunc = crypto.SHA256
	case AlgorithmECCP384:
		curve = elliptic.P384()
		hashFunc = crypto.SHA384
	default:
		return fmt.Errorf("unsupported ECDSA algorithm: %s", algorithm)
	}

	curveSize := (curve.Params().BitSize + 7) / 8
	expectedBytes := 4 * curveSize
	
	if len(combined) != expectedBytes {
		return fmt.Errorf("invalid signature block size: expected %d, got %d", expectedBytes, len(combined))
	}

	X := new(big.Int).SetBytes(safePad(combined[0:curveSize], curveSize))
	Y := new(big.Int).SetBytes(safePad(combined[curveSize:2*curveSize], curveSize))
	R := new(big.Int).SetBytes(safePad(combined[2*curveSize:3*curveSize], curveSize))
	S := new(big.Int).SetBytes(safePad(combined[3*curveSize:], curveSize))

	if !curve.IsOnCurve(X, Y) {
		return fmt.Errorf("public key point is not on the curve")
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     X,
		Y:     Y,
	}

	var digest []byte
	switch hashFunc {
	case crypto.SHA256:
		h := sha256.New()
		h.Write(data)
		digest = h.Sum(nil)
	case crypto.SHA384:
		h := sha512.New384()
		h.Write(data)
		digest = h.Sum(nil)
	}

	if !ecdsa.Verify(pub, digest, R, S) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// extractPublicKeyFromSignature extracts the public key from the signature
func extractPublicKeyFromSignature(combined []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case AlgorithmED25519:
		if len(combined) != Ed25519CombinedSize {
			return nil, fmt.Errorf("invalid Ed25519 signature block")
		}
		return combined[:Ed25519PublicKeySize], nil
	case AlgorithmECCP256, AlgorithmECCP384:
		var curve elliptic.Curve
		switch algorithm {
		case AlgorithmECCP256:
			curve = elliptic.P256()
		case AlgorithmECCP384:
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("unsupported ECDSA algorithm: %s", algorithm)
		}
		curveSize := (curve.Params().BitSize + 7) / 8
		expectedBytes := 4 * curveSize
		if len(combined) != expectedBytes {
			return nil, fmt.Errorf("invalid signature block size: expected %d, got %d", expectedBytes, len(combined))
		}
		return combined[:2*curveSize], nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// onClear resets the UI
func (g *GUI) onClear() {
	g.authorEntry.SetText("")
	g.emailEntry.SetText("")
	g.urlEntry.SetText("")
	g.pinEntry.SetText("")
	g.currentFile = ""
	g.signaturePath = ""
	g.fileSelected = false
	g.filenameLabel.SetText("No file selected")
	g.filesizeLabel.SetText("")
	g.filesizeLabel.Hide()
	g.sigDisplay.SetText("")
	g.encryptionUsed = false
	g.progressBar.Hide()
	g.progressLabel.Hide()
	g.statusLabel.SetText("Cleared all fields")
}

// Helper functions
func safePad(b []byte, size int) []byte {
	if len(b) > size {
		return b[len(b)-size:]
	}
	return append(make([]byte, size-len(b)), b...)
}

func formatSignatureRFC(sig string) string {
	var result strings.Builder
	for i := 0; i < len(sig); i += 64 {
		end := i + 64
		if end > len(sig) {
			end = len(sig)
		}
		result.WriteString(sig[i:end])
		result.WriteString("\r\n")
	}
	return result.String()
}

func formatByteSize(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func stripLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	return b[i:]
}

func extractPublicKeyDisplayBytes(combined []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case AlgorithmED25519:
		if len(combined) != Ed25519CombinedSize {
			return nil, fmt.Errorf("invalid Ed25519 signature block")
		}
		return combined[:Ed25519PublicKeySize], nil
	case AlgorithmECCP256, AlgorithmECCP384:
		var curve elliptic.Curve
		switch algorithm {
		case AlgorithmECCP256:
			curve = elliptic.P256()
		case AlgorithmECCP384:
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("unsupported ECDSA algorithm: %s", algorithm)
		}
		curveSize := (curve.Params().BitSize + 7) / 8
		expectedBytes := 4 * curveSize
		if len(combined) != expectedBytes {
			return nil, fmt.Errorf("invalid signature block size: expected %d, got %d", expectedBytes, len(combined))
		}
		XBytes := combined[0:curveSize]
		YBytes := combined[curveSize : 2*curveSize]
		XStripped := stripLeadingZeros(XBytes)
		YStripped := stripLeadingZeros(YBytes)
		result := make([]byte, 0, len(XStripped)+len(YStripped))
		result = append(result, XStripped...)
		result = append(result, YStripped...)
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func openYubiKey(index int) (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("failed to list cards: %v", err)
	}
	if len(cards) == 0 {
		return nil, fmt.Errorf("no smart card found")
	}
	count := 0
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if count == index {
				return piv.Open(card)
			}
			count++
		}
	}
	return nil, fmt.Errorf("no YubiKey found at index %d", index)
}

// ClassicIdenticon implementation
type ClassicIdenticon struct {
	source []byte
	size   int
}

func NewClassicIdenticon(source []byte) *ClassicIdenticon {
	return &ClassicIdenticon{
		source: source,
		size:   256,
	}
}

func (identicon *ClassicIdenticon) getBit(n int) bool {
	if len(identicon.source) == 0 || n < 0 {
		return false
	}
	byteIndex := n / 8
	bitIndex := n % 8
	if byteIndex >= len(identicon.source) {
		return false
	}
	return (identicon.source[byteIndex]>>bitIndex)&1 == 1
}

func (identicon *ClassicIdenticon) foreground() color.Color {
	if len(identicon.source) < 32 {
		return color.RGBA{0, 0, 0, 255}
	}
	colorIndex := 0
	for i := 0; i < 4; i++ {
		if identicon.getBit(248 + i) {
			colorIndex |= 1 << i
		}
	}
	colorIndex %= 16
	
	palette := []color.RGBA{
		{0x00, 0xbf, 0x93, 0xff},
		{0x2d, 0xcc, 0x70, 0xff},
		{0x42, 0xe4, 0x53, 0xff},
		{0xf1, 0xc4, 0x0f, 0xff},
		{0xe6, 0x7f, 0x22, 0xff},
		{0xff, 0x94, 0x4e, 0xff},
		{0xe8, 0x4c, 0x3d, 0xff},
		{0x35, 0x98, 0xdb, 0xff},
		{0x9a, 0x59, 0xb5, 0xff},
		{0xef, 0x3e, 0x96, 0xff},
		{0xdf, 0x21, 0xb9, 0xff},
		{0x7d, 0xc2, 0xd2, 0xff},
		{0x16, 0xa0, 0x86, 0xff},
		{0x27, 0xae, 0x61, 0xff},
		{0x24, 0xc3, 0x33, 0xff},
		{0x1c, 0xab, 0xbb, 0xff},
	}
	return palette[colorIndex]
}

func (identicon *ClassicIdenticon) secondaryColor() color.Color {
	if len(identicon.source) < 32 {
		return color.RGBA{100, 100, 100, 255}
	}
	colorIndex := 0
	for i := 0; i < 4; i++ {
		if identicon.getBit(244 + i) {
			colorIndex |= 1 << i
		}
	}
	colorIndex %= 16
	
	palette := []color.RGBA{
		{0x34, 0x49, 0x5e, 0xff},
		{0x95, 0xa5, 0xa5, 0xff},
		{0xd2, 0x54, 0x00, 0xff},
		{0xc1, 0x39, 0x2b, 0xff},
		{0x29, 0x7f, 0xb8, 0xff},
		{0x8d, 0x44, 0xad, 0xff},
		{0xbe, 0x12, 0x7e, 0xff},
		{0xe5, 0x23, 0x83, 0xff},
		{0x27, 0xae, 0x61, 0xff},
		{0x24, 0xc3, 0x33, 0xff},
		{0xd9, 0xd9, 0x21, 0xff},
		{0xf3, 0x9c, 0x11, 0xff},
		{0xff, 0x55, 0x00, 0xff},
		{0x1c, 0xab, 0xbb, 0xff},
		{0x23, 0x23, 0x23, 0xff},
		{0x7e, 0x8c, 0x8d, 0xff},
	}
	return palette[colorIndex]
}

func (identicon *ClassicIdenticon) generatePixelPattern() ([]bool, []bool) {
	primary := make([]bool, 25)
	secondary := make([]bool, 25)
	
	bitIndex := 0
	for row := 0; row < 5; row++ {
		for col := 0; col < 3; col++ {
			paint := identicon.getBit(bitIndex)
			bitIndex++
			ix := row*5 + col
			mirrorIx := row*5 + (4 - col)
			primary[ix] = paint
			primary[mirrorIx] = paint
		}
	}
	
	for row := 0; row < 5; row++ {
		for col := 0; col < 3; col++ {
			paint := identicon.getBit(bitIndex)
			bitIndex++
			ix := row*5 + col
			mirrorIx := row*5 + (4 - col)
			secondary[ix] = paint
			secondary[mirrorIx] = paint
		}
	}
	
	return primary, secondary
}

func (identicon *ClassicIdenticon) drawRect(img *image.RGBA, x0, y0, x1, y1 int, c color.Color) {
	r, g, b, a := c.RGBA()
	rgba := color.RGBA{
		R: uint8(r >> 8),
		G: uint8(g >> 8),
		B: uint8(b >> 8),
		A: uint8(a >> 8),
	}
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			img.SetRGBA(x, y, rgba)
		}
	}
}

func (identicon *ClassicIdenticon) Generate() image.Image {
	const (
		pixelSize  = 36
		spriteSize = 5
		margin     = (256 - pixelSize*spriteSize) / 2
	)
	
	primaryColor := identicon.foreground()
	secondaryColor := identicon.secondaryColor()
	img := image.NewRGBA(image.Rect(0, 0, identicon.size, identicon.size))
	
	// Background
	bgChoice := 0
	for i := 0; i < 2; i++ {
		if identicon.getBit(252 + i) {
			bgChoice |= 1 << i
		}
	}
	bgChoice %= 3
	
	var bg color.RGBA
	if fyne.CurrentApp().Settings().ThemeVariant() == theme.VariantDark {
		darkBackgrounds := []color.RGBA{
			{30, 30, 30, 255},
			{45, 62, 80, 255},
			{57, 57, 57, 255},
		}
		bg = darkBackgrounds[bgChoice]
	} else {
		lightBackgrounds := []color.RGBA{
			{255, 255, 255, 255},
			{243, 245, 247, 255},
			{236, 240, 241, 255},
		}
		bg = lightBackgrounds[bgChoice]
	}
	
	for y := 0; y < identicon.size; y++ {
		for x := 0; x < identicon.size; x++ {
			img.SetRGBA(x, y, bg)
		}
	}
	
	primaryPixels, secondaryPixels := identicon.generatePixelPattern()
	
	// Draw secondary pixels
	for row := 0; row < spriteSize; row++ {
		for col := 0; col < spriteSize; col++ {
			if secondaryPixels[row*spriteSize+col] {
				x := col*pixelSize + margin
				y := row*pixelSize + margin
				identicon.drawRect(img, x, y, x+pixelSize, y+pixelSize, secondaryColor)
			}
		}
	}
	
	// Draw primary pixels
	for row := 0; row < spriteSize; row++ {
		for col := 0; col < spriteSize; col++ {
			if primaryPixels[row*spriteSize+col] {
				x := col*pixelSize + margin
				y := row*pixelSize + margin
				identicon.drawRect(img, x, y, x+pixelSize, y+pixelSize, primaryColor)
			}
		}
	}
	
	return img
}
