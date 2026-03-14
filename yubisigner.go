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
	"net/url"
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

// MerkleTree node structure
type MerkleNode struct {
	Hash  string
	Left  *MerkleNode
	Right *MerkleNode
}

// FileHashEntry stores file path and hash for Merkle tree
type FileHashEntry struct {
	Path string
	Hash string
}

// SignatureMetadata stores metadata about the signature
type SignatureMetadata struct {
	Author    string
	Email     string
	URL       string
	Filename  string
	FileSize  int64
	Timestamp time.Time
}

// ecSignature represents an ECDSA signature with R and S components
type ecSignature struct{ R, S *big.Int }

// Supported algorithms constants
const (
	AlgorithmECCP256 = "ECCP256"
	AlgorithmECCP384 = "ECCP384"
	AlgorithmED25519 = "ED25519"
)

// Map of supported algorithms
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

// Minimum RSA key bits
const (
	minRSABits = 2048
)

// Supported RSA key sizes
var supportedRSASizes = map[int]string{
	2048: "RSA2048",
	3072: "RSA3072",
	4096: "RSA4096",
}

// RFC 5322 compliant email regex pattern
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// GUI structure with all UI components
type GUI struct {
	app            fyne.App
	window         fyne.Window
	themeToggle    *widget.Button
	infoBtn        *widget.Button
	pinEntry       *widget.Entry
	statusLabel    *widget.Label
	authorEntry    *widget.Entry
	emailEntry     *widget.Entry
	urlEntry       *widget.Entry
	telefaxEntry   *widget.Entry
	commentEntry   *widget.Entry
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

// main initializes and runs the application
func main() {
	defer memguard.Purge()

	// NOTE: Removed os.Setenv for LANG and LC_ALL to prevent theme conflicts

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
	gui.window.Resize(fyne.NewSize(600, 520))
	gui.createUI()
	gui.applyTheme()
	gui.window.SetContent(gui.createMainUI())
	gui.window.CenterOnScreen()
	gui.window.ShowAndRun()
}

// createUI initializes all UI components
func (g *GUI) createUI() {
	// Author Entry (Required field)
	g.authorEntry = widget.NewEntry()
	g.authorEntry.SetPlaceHolder("required")
	g.authorEntry.Validator = func(s string) error {
		if s == "" {
			return fmt.Errorf("Author is required")
		}
		return nil
	}

	// Email Entry (Optional, RFC-compliant validation)
	g.emailEntry = widget.NewEntry()
	g.emailEntry.SetPlaceHolder("optional")
	g.emailEntry.Validator = func(s string) error {
		if s == "" {
			return nil
		}
		if !emailRegex.MatchString(s) {
			return fmt.Errorf("invalid email format")
		}
		return nil
	}

	// URL Entry (Optional)
	g.urlEntry = widget.NewEntry()
	g.urlEntry.SetPlaceHolder("optional")

	// Telefax Entry (Optional, must start with '+' for international format)
	g.telefaxEntry = widget.NewEntry()
	g.telefaxEntry.SetPlaceHolder("optional")
	g.telefaxEntry.Validator = func(s string) error {
		if s == "" {
			return nil
		}
		if !strings.HasPrefix(s, "+") {
			return fmt.Errorf("Telefax must start with '+' for international format")
		}
		return nil
	}

	// Comment Entry (Optional, UTF-8 supported)
	g.commentEntry = widget.NewEntry()
	g.commentEntry.SetPlaceHolder("optional")

	// Filename Label (shows selected file name)
	g.filenameLabel = widget.NewLabel("No file selected")
	g.filenameLabel.TextStyle = fyne.TextStyle{Italic: true}

	// Filesize Label (shows file size in bytes)
	g.filesizeLabel = widget.NewLabel("")
	g.filesizeLabel.TextStyle = fyne.TextStyle{Monospace: true}
	g.filesizeLabel.Hide()

	// PIN Entry (password field, max 8 ASCII characters)
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

	// Status Label (shows current operation status)
	g.statusLabel = widget.NewLabel("Ready")
	g.statusLabel.Wrapping = fyne.TextWrapWord

	// Signature Display (shows existing signature file)
	g.sigDisplay = widget.NewLabel("")
	g.sigDisplay.TextStyle = fyne.TextStyle{Italic: true}

	// Progress bar for large file operations
	g.progressBar = widget.NewProgressBar()
	g.progressBar.Min = 0
	g.progressBar.Max = 1
	g.progressBar.Hide()

	// Progress percentage label
	g.progressLabel = widget.NewLabel("")
	g.progressLabel.Alignment = fyne.TextAlignCenter
	g.progressLabel.Hide()

	// Theme Toggle Button (switch between light/dark theme)
	g.themeToggle = widget.NewButton("☀️", g.toggleTheme)

	// Info Button (top left, shows project information)
	g.infoBtn = widget.NewButtonWithIcon("", theme.InfoIcon(), g.showInfoPopup)
}

// createMainUI builds the main layout with all buttons and fields
func (g *GUI) createMainUI() fyne.CanvasObject {
	// Main action buttons (Sign, Verify, CMT, VMT)
	signBtn := widget.NewButton("Sign", g.onSignClick)
	signBtn.Importance = widget.HighImportance

	verifyBtn := widget.NewButton("Verify", g.onVerifyClick)
	verifyBtn.Importance = widget.HighImportance

	cmtBtn := widget.NewButton("CMT", g.onCreateMerkleTree)
	cmtBtn.Importance = widget.HighImportance

	vmtBtn := widget.NewButton("VMT", g.onVerifyMerkleTree)
	vmtBtn.Importance = widget.HighImportance

	// All four buttons centered in one row
	buttonContainer := container.NewCenter(
		container.NewVBox(
			container.NewHBox(
				signBtn,
				verifyBtn,
				cmtBtn,
				vmtBtn,
			),
		),
	)

	// Top Bar: Info button (Left), Theme toggle (Right)
	topBar := container.NewHBox(
		g.infoBtn,
		layout.NewSpacer(),
		g.themeToggle,
	)

	// Metadata grid with all input fields
	metadataGrid := container.New(layout.NewFormLayout(),
		widget.NewLabel("Author:"),
		g.authorEntry,
		widget.NewLabel("Email:"),
		g.emailEntry,
		widget.NewLabel("Telefax:"),
		g.telefaxEntry,
		widget.NewLabel("URL:"),
		g.urlEntry,
		widget.NewLabel("Comment:"),
		g.commentEntry,
	)

	// File info container with filename and filesize
	fileInfoContainer := container.NewVBox(
		g.filenameLabel,
		g.filesizeLabel,
	)

	// Clear Button (resets all fields)
	clearBtn := widget.NewButton("Clear", g.onClear)
	clearBtn.Importance = widget.HighImportance

	// PIN Container with label, entry and clear button
	pinContainer := container.NewHBox(
		layout.NewSpacer(),
		widget.NewLabel("PIN:"),
		g.pinEntry,
		clearBtn,
		layout.NewSpacer(),
	)

	// Progress Container with label and progress bar
	progressContainer := container.NewVBox(
		g.progressLabel,
		g.progressBar,
	)

	// Main top container with all content
	topContainer := container.NewVBox(
		topBar,
		widget.NewSeparator(),
		buttonContainer,
		widget.NewSeparator(),
		metadataGrid,
		fileInfoContainer,
		widget.NewSeparator(),
		g.sigDisplay,
		progressContainer,
	)

	// Bottom container with PIN and status
	bottomContainer := container.NewVBox(
		widget.NewSeparator(),
		pinContainer,
		g.statusLabel,
	)

	// Main border layout
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

// applyTheme sets the initial theme on startup
func (g *GUI) applyTheme() {
	if g.currentTheme == "dark" {
		g.app.Settings().SetTheme(theme.DarkTheme())
		g.themeToggle.SetText("☀️")
	} else {
		g.app.Settings().SetTheme(theme.LightTheme())
		g.themeToggle.SetText("🌙")
	}
}

// showInfoPopup displays project information dialog
func (g *GUI) showInfoPopup() {
	projURL, _ := url.Parse("https://github.com/Ch1ffr3punk/yubisigner")
	projectLink := widget.NewHyperlink("An Open Source project", projURL)

	okButton := widget.NewButton("OK", func() {
		overlays := g.window.Canvas().Overlays()
		if overlays.Top() != nil {
			overlays.Remove(overlays.Top())
		}
	})
	okButton.Importance = widget.HighImportance

	content := container.NewVBox(
		widget.NewLabelWithStyle("yubisigner v0.1.3", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		container.NewHBox(
			layout.NewSpacer(),
			projectLink,
			layout.NewSpacer(),
		),
		widget.NewLabelWithStyle("released under the Apache 2.0 license", fyne.TextAlignCenter, fyne.TextStyle{}),
		widget.NewLabelWithStyle("© 2026 Ch1ffr3punk", fyne.TextAlignCenter, fyne.TextStyle{}),
		widget.NewLabel(""),
		container.NewHBox(
			layout.NewSpacer(),
			okButton,
			layout.NewSpacer(),
		),
	)

	dialog.ShowCustomWithoutButtons("", content, g.window)
}

// selectFile opens the Fyne file dialog for file selection
// FIX: Removed g.window.Content().Refresh() to prevent button rendering issues
func (g *GUI) selectFile(callback func()) {
	// Store previous file path
	previousFile := g.currentFile

	// Create the file open dialog
	fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil {
			g.statusLabel.SetText("Error selecting file: " + err.Error())
			return
		}
		if reader == nil {
			// Dialog was cancelled
			g.currentFile = previousFile
			return
		}
		defer reader.Close()

		// File was selected and "Open" clicked
		g.currentFile = reader.URI().Path()
		g.filenameLabel.SetText(filepath.Base(g.currentFile))
		g.signaturePath = g.currentFile + ".sig"
		g.fileSelected = true

		fileInfo, err := os.Stat(g.currentFile)
		if err != nil {
			g.statusLabel.SetText("Error getting file info: " + err.Error())
			return
		}
		fileSize := fileInfo.Size()
		g.filesizeLabel.SetText(fmt.Sprintf("Size: %d bytes (%s)",
			fileSize, formatByteSize(int(fileSize))))
		g.filesizeLabel.Show()
		g.statusLabel.SetText(fmt.Sprintf("Selected: %s", filepath.Base(g.currentFile)))

		if _, err := os.Stat(g.signaturePath); err == nil {
			g.sigDisplay.SetText("✓ " + filepath.Base(g.signaturePath))
		} else {
			g.sigDisplay.SetText("")
		}

		if callback != nil {
			callback()
		}
	}, g.window)

	// Set filter to show all files
	fileDialog.SetFilter(nil)

	// FIX: Show dialog in fyne.Do() to ensure proper rendering on overlay
	fyne.Do(func() {
		fileDialog.Show()
	})
}

// onSignClick handles the Sign button click - always opens file dialog
func (g *GUI) onSignClick() {
	g.signingMode = true
	g.selectFile(func() {
		g.continueSign()
	})
}

// selectDirectory opens directory dialog for Merkle tree operations
func (g *GUI) selectDirectory(callback func(string)) {
	folderDialog := dialog.NewFolderOpen(func(list fyne.ListableURI, err error) {
		if err != nil {
			g.statusLabel.SetText("Error selecting directory: " + err.Error())
			return
		}
		if list == nil {
			return
		}
		dirPath := list.Path()
		g.filenameLabel.SetText(filepath.Base(dirPath) + "/")
		g.currentFile = dirPath
		g.fileSelected = true
		g.filesizeLabel.SetText("Directory")
		g.filesizeLabel.Show()
		g.statusLabel.SetText(fmt.Sprintf("Selected directory: %s", filepath.Base(dirPath)))
		g.sigDisplay.SetText("")
		if callback != nil {
			callback(dirPath)
		}
	}, g.window)
	folderDialog.Show()
}

// showPinDialog shows a modal PIN entry dialog
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

// validateEmail checks RFC 5322 compliant email format
func validateEmail(email string) error {
	if email == "" {
		return nil
	}
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// validateTelefax checks international fax format (must start with '+')
func validateTelefax(telefax string) error {
	if telefax == "" {
		return nil
	}
	if !strings.HasPrefix(telefax, "+") {
		return fmt.Errorf("Telefax must start with '+' for international format")
	}
	return nil
}

// onCreateMerkleTree handles the Create Merkle Tree button click
func (g *GUI) onCreateMerkleTree() {
	g.selectDirectory(func(dirPath string) {
		g.continueCreateMerkleTree(dirPath)
	})
}

// continueCreateMerkleTree continues Merkle tree creation after directory selection
func (g *GUI) continueCreateMerkleTree(dirPath string) {
	g.statusLabel.SetText(fmt.Sprintf("Creating Merkle tree for %s...", filepath.Base(dirPath)))

	// Show progress indicators
	g.progressBar.SetValue(0)
	g.progressBar.Show()
	g.progressLabel.SetText("Scanning files...")
	g.progressLabel.Show()

	go func() {
		startTime := time.Now()

		// Collect all files recursively
		var fileEntries []FileHashEntry
		var totalFiles int

		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				totalFiles++
			}
			return nil
		})
		if err != nil {
			g.showErrorAsync("Error scanning directory: " + err.Error())
			return
		}

		// Process files with progress updates
		processedFiles := 0
		err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				// Get relative path
				relPath, err := filepath.Rel(dirPath, path)
				if err != nil {
					relPath = path
				}

				// Skip the merkle-tree.txt file itself if it exists
				if relPath == "merkle-tree.txt" {
					processedFiles++
					return nil
				}

				// Calculate RIPEMD-160 hash
				hash, err := calculateRIPEMD160File(path)
				if err != nil {
					g.updateStatusAsync(fmt.Sprintf("Error hashing %s: %v", relPath, err))
					return nil
				}

				fileEntries = append(fileEntries, FileHashEntry{
					Path: relPath,
					Hash: hash,
				})
				processedFiles++

				progress := float64(processedFiles) / float64(totalFiles)
				fyne.Do(func() {
					g.progressBar.SetValue(progress)
					g.progressLabel.SetText(fmt.Sprintf("Hashing files: %d/%d (%.0f%%)",
						processedFiles, totalFiles, progress*100))
				})
			}
			return nil
		})
		if err != nil {
			g.showErrorAsync("Error walking directory: " + err.Error())
			return
		}

		// Sort entries by path for consistent ordering
		sort.Slice(fileEntries, func(i, j int) bool {
			return fileEntries[i].Path < fileEntries[j].Path
		})

		// Build Merkle tree to get root hash
		g.updateStatusAsync("Building Merkle tree...")
		rootHash := buildMerkleTreeRoot(fileEntries)

		// Build output with CRLF line endings
		var output strings.Builder
		output.WriteString("--- FILE HASHES (RIPEMD-160) ---\r\n")
		for _, entry := range fileEntries {
			output.WriteString(fmt.Sprintf("%s: %s\r\n", entry.Path, entry.Hash))
		}
		output.WriteString("\r\n")
		output.WriteString("--- ROOT HASH (RIPEMD-160) ---\r\n")
		output.WriteString(fmt.Sprintf("%s\r\n", rootHash))

		// Write to file
		outputFile := filepath.Join(dirPath, "merkle-tree.txt")
		err = os.WriteFile(outputFile, []byte(output.String()), 0644)
		if err != nil {
			g.showErrorAsync("Error writing Merkle tree file: " + err.Error())
			return
		}

		elapsedTime := time.Since(startTime).Seconds()
		fyne.Do(func() {
			g.progressBar.Hide()
			g.progressLabel.Hide()
			g.statusLabel.SetText(fmt.Sprintf("✓ Merkle tree created: %s (%.1f seconds, %d files)",
				"merkle-tree.txt", elapsedTime, len(fileEntries)))
			g.sigDisplay.SetText("✓ merkle-tree.txt")
		})
	}()
}

// buildMerkleTreeRoot builds a Merkle tree and returns only the root hash
func buildMerkleTreeRoot(entries []FileHashEntry) string {
	if len(entries) == 0 {
		return ""
	}

	// Start with leaf hashes
	var currentLevel []string
	for _, entry := range entries {
		currentLevel = append(currentLevel, entry.Hash)
	}

	// Build tree bottom-up until we get the root
	for len(currentLevel) > 1 {
		var nextLevel []string
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				// Combine two nodes
				combined := currentLevel[i] + currentLevel[i+1]
				hash := calculateRIPEMD160(combined)
				nextLevel = append(nextLevel, hash)
			} else {
				// Odd node, promote to next level
				nextLevel = append(nextLevel, currentLevel[i])
			}
		}
		currentLevel = nextLevel
	}

	// Root hash is the last remaining node
	if len(currentLevel) == 1 {
		return currentLevel[0]
	}
	return ""
}

// onVerifyMerkleTree handles the Verify Merkle Tree button click
func (g *GUI) onVerifyMerkleTree() {
	g.selectDirectory(func(dirPath string) {
		g.continueVerifyMerkleTree(dirPath)
	})
}

// continueVerifyMerkleTree continues Merkle tree verification
func (g *GUI) continueVerifyMerkleTree(dirPath string) {
	// Check if merkle-tree.txt exists
	merkleFilePath := filepath.Join(dirPath, "merkle-tree.txt")
	merkleData, err := os.ReadFile(merkleFilePath)
	if err != nil {
		dialog.ShowError(fmt.Errorf("merkle-tree.txt not found in selected directory"), g.window)
		return
	}

	g.statusLabel.SetText("Verifying Merkle tree...")
	g.progressBar.SetValue(0)
	g.progressBar.Show()
	g.progressLabel.SetText("Parsing Merkle tree file...")
	g.progressLabel.Show()

	go func() {
		startTime := time.Now()

		// Parse the merkle-tree.txt file
		content := string(merkleData)
		lines := strings.Split(content, "\r\n")

		// Extract data
		var fileHashes []FileHashEntry
		var rootHashFromFile string
		section := ""

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Check for section headers
			if line == "--- FILE HASHES (RIPEMD-160) ---" {
				section = "file_hashes"
				continue
			} else if line == "--- ROOT HASH (RIPEMD-160) ---" {
				section = "root_hash"
				continue
			}

			// Parse based on section
			switch section {
			case "file_hashes":
				if strings.Contains(line, ":") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						filePath := strings.TrimSpace(parts[0])
						fileHash := strings.TrimSpace(parts[1])
						fileHashes = append(fileHashes, FileHashEntry{
							Path: filePath,
							Hash: fileHash,
						})
					}
				}
			case "root_hash":
				if len(line) == 40 {
					rootHashFromFile = line
				}
			}
		}

		// Verify by recalculating hashes
		g.updateStatusAsync("Recalculating file hashes...")
		var currentFileHashes []FileHashEntry
		var totalFiles int

		// Count total files for progress
		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				relPath, _ := filepath.Rel(dirPath, path)
				if relPath != "merkle-tree.txt" {
					totalFiles++
				}
			}
			return nil
		})

		processedFiles := 0
		err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				relPath, err := filepath.Rel(dirPath, path)
				if err != nil {
					relPath = path
				}

				if relPath == "merkle-tree.txt" {
					processedFiles++
					return nil
				}

				hash, err := calculateRIPEMD160File(path)
				if err != nil {
					g.updateStatusAsync(fmt.Sprintf("Error hashing %s: %v", relPath, err))
					return nil
				}

				currentFileHashes = append(currentFileHashes, FileHashEntry{
					Path: relPath,
					Hash: hash,
				})
				processedFiles++

				progress := float64(processedFiles) / float64(totalFiles)
				fyne.Do(func() {
					g.progressBar.SetValue(progress)
					g.progressLabel.SetText(fmt.Sprintf("Verifying: %d/%d (%.0f%%)",
						processedFiles, totalFiles, progress*100))
				})
			}
			return nil
		})
		if err != nil {
			g.showErrorAsync("Error walking directory: " + err.Error())
			return
		}

		// Sort by path
		sort.Slice(currentFileHashes, func(i, j int) bool {
			return currentFileHashes[i].Path < currentFileHashes[j].Path
		})

		// Compare file counts
		if len(currentFileHashes) != len(fileHashes) {
			fyne.Do(func() {
				g.showErrorPopup(fmt.Sprintf("File count mismatch: expected %d, found %d",
					len(fileHashes), len(currentFileHashes)), nil)
			})
			return
		}

		// Compare individual file hashes
		hashMismatch := false
		for i := 0; i < len(fileHashes); i++ {
			if i >= len(currentFileHashes) {
				hashMismatch = true
				break
			}
			if fileHashes[i].Path != currentFileHashes[i].Path ||
				fileHashes[i].Hash != currentFileHashes[i].Hash {
				hashMismatch = true
				g.updateStatusAsync(fmt.Sprintf("Mismatch: %s", fileHashes[i].Path))
				break
			}
		}

		if hashMismatch {
			fyne.Do(func() {
				g.showErrorPopup("File hash mismatch detected", nil)
			})
			return
		}

		// Rebuild Merkle tree to verify root hash
		g.updateStatusAsync("Rebuilding Merkle tree...")
		calculatedRootHash, _ := buildMerkleTree(currentFileHashes)

		// Compare root hashes
		if calculatedRootHash != rootHashFromFile {
			fyne.Do(func() {
				g.showErrorPopup(fmt.Sprintf("Root hash mismatch:\nExpected: %s\nCalculated: %s",
					rootHashFromFile, calculatedRootHash), nil)
			})
			return
		}

		elapsedTime := time.Since(startTime).Seconds()
		fyne.Do(func() {
			g.progressBar.Hide()
			g.progressLabel.Hide()
			g.statusLabel.SetText(fmt.Sprintf("✓ Merkle tree verified successfully (%.1f seconds, %d files)",
				elapsedTime, len(currentFileHashes)))

			// Create identicon from root hash
			hashBytes, _ := hex.DecodeString(calculatedRootHash)
			hexString := hex.EncodeToString(hashBytes)
			hashForIdenticon := sha256.Sum256([]byte(hexString))
			g.showSuccessPopupWithIdenticon(hashForIdenticon[:])
		})
	}()
}

// calculateRIPEMD160File calculates RIPEMD-160 hash of a file
func calculateRIPEMD160File(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := ripemd.New160()
	buf := make([]byte, 32*1024*1024)

	for {
		n, err := file.Read(buf)
		if n > 0 {
			hasher.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// buildMerkleTree builds a Merkle tree from file hash entries
func buildMerkleTree(entries []FileHashEntry) (string, []string) {
	if len(entries) == 0 {
		return "", []string{}
	}

	var currentLevel []string
	for _, entry := range entries {
		currentLevel = append(currentLevel, entry.Hash)
	}

	var allNodes []string
	allNodes = append(allNodes, currentLevel...)

	for len(currentLevel) > 1 {
		var nextLevel []string
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				combined := currentLevel[i] + currentLevel[i+1]
				hash := calculateRIPEMD160(combined)
				nextLevel = append(nextLevel, hash)
				allNodes = append(allNodes, hash)
			} else {
				nextLevel = append(nextLevel, currentLevel[i])
			}
		}
		currentLevel = nextLevel
	}

	if len(currentLevel) == 1 {
		return currentLevel[0], allNodes
	}
	return "", allNodes
}

// calculateRIPEMD160 calculates RIPEMD-160 hash of a string
func calculateRIPEMD160(data string) string {
	hasher := ripemd.New160()
	hasher.Write([]byte(data))
	return hex.EncodeToString(hasher.Sum(nil))
}

// continueSign continues the signing process after file selection
func (g *GUI) continueSign() {
	if g.currentFile == "" {
		g.statusLabel.SetText("Error: No file selected")
		return
	}

	// Validate Author (Required)
	author := g.authorEntry.Text
	if strings.TrimSpace(author) == "" {
		dialog.ShowError(fmt.Errorf("Author field is required"), g.window)
		return
	}
	author = ensureUTF8(author)

	// Validate Email
	email := g.emailEntry.Text
	if err := validateEmail(email); err != nil {
		dialog.ShowError(err, g.window)
		return
	}

	// Validate Telefax
	telefax := g.telefaxEntry.Text
	if err := validateTelefax(telefax); err != nil {
		dialog.ShowError(err, g.window)
		return
	}

	// Check PIN
	if g.pinEntry.Text == "" {
		g.showPinDialog("PIN required for signing", func(pin string) {
			g.pinEntry.SetText(pin)
			g.continueSign()
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

	g.statusLabel.SetText(fmt.Sprintf("Preparing to sign %s (%s)...",
		filepath.Base(g.currentFile), formatByteSize(int(fileSize))))

	// Decide strategy based on file size
	if fileSize <= 1024*1024*1024 {
		// <= 1GB - load into RAM
		g.progressBar.SetValue(0)
		g.progressBar.Show()
		g.progressLabel.SetText("Loading file...")
		g.progressLabel.Show()
		g.statusLabel.SetText(fmt.Sprintf("Loading %s into RAM...", filepath.Base(g.currentFile)))

		go func() {
			startTime := time.Now()

			file, err := os.Open(g.currentFile)
			if err != nil {
				g.showErrorAsync("Error opening file: " + err.Error())
				return
			}

			var data []byte
			buf := make([]byte, 32*1024*1024)
			bytesRead := int64(0)

			for {
				n, err := file.Read(buf)
				if n > 0 {
					data = append(data, buf[:n]...)
					bytesRead += int64(n)
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

			fyne.Do(func() {
				g.progressLabel.SetText("Calculating hashes...")
			})

			hashes := g.calculateHashesRAM(data)

			// Prepare metadata
			if email == "" {
				email = "n/a"
			}
			url := g.urlEntry.Text
			if url == "" {
				url = "n/a"
			}
			if telefax == "" {
				telefax = "n/a"
			}
			comment := g.commentEntry.Text
			if comment == "" {
				comment = "n/a"
			} else {
				comment = ensureUTF8(comment)
			}

			// Build metadata section
			metadata := fmt.Sprintf("Author: %s\r\n", author)
			metadata += fmt.Sprintf("Signed at: %s\r\n", time.Now().UTC().Format("2006-01-02 15:04:05 +0000"))
			metadata += fmt.Sprintf("Filename: %s\r\n", filepath.Base(g.currentFile))
			metadata += fmt.Sprintf("File size: %d bytes\r\n", fileSize)
			metadata += fmt.Sprintf("Email: %s\r\n", email)
			metadata += fmt.Sprintf("Telefax: %s\r\n", telefax)
			metadata += fmt.Sprintf("URL: %s\r\n", url)
			metadata += fmt.Sprintf("Comment: %s\r\n", comment)
			metadata += g.formatHashes(hashes)

			fyne.Do(func() {
				g.progressLabel.SetText("Signing metadata...")
			})

			sig, algo, err := g.signDataInternal([]byte(g.pinEntry.Text), []byte(metadata))
			if err != nil {
				g.showErrorAsync("Signing failed: " + err.Error())
				return
			}

			result := metadata
			result += "-----BEGIN YUBISIGNER " + algo + " SIGNATURE-----\r\n"
			result += formatSignatureRFC(sig)
			result += "-----END YUBISIGNER " + algo + " SIGNATURE-----\r\n"

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
	} else {
		// > 1GB - use optimized chunking
		g.progressBar.SetValue(0)
		g.progressBar.Show()
		g.progressLabel.SetText("0%")
		g.progressLabel.Show()
		g.statusLabel.SetText(fmt.Sprintf("Processing large file (%s)...", formatByteSize(int(fileSize))))

		go func() {
			startTime := time.Now()

			hashes, err := g.calculateFileHashesOptimized(g.currentFile)
			if err != nil {
				g.showErrorAsync("Error reading file: " + err.Error())
				return
			}

			// Prepare metadata
			if email == "" {
				email = "n/a"
			}
			url := g.urlEntry.Text
			if url == "" {
				url = "n/a"
			}
			if telefax == "" {
				telefax = "n/a"
			}
			comment := g.commentEntry.Text
			if comment == "" {
				comment = "n/a"
			} else {
				comment = ensureUTF8(comment)
			}

			metadata := fmt.Sprintf("Author: %s\r\n", author)
			metadata += fmt.Sprintf("Signed at: %s\r\n", time.Now().UTC().Format("2006-01-02 15:04:05 +0000"))
			metadata += fmt.Sprintf("Filename: %s\r\n", filepath.Base(g.currentFile))
			metadata += fmt.Sprintf("File size: %d bytes\r\n", fileSize)
			metadata += fmt.Sprintf("Email: %s\r\n", email)
			metadata += fmt.Sprintf("Telefax: %s\r\n", telefax)
			metadata += fmt.Sprintf("URL: %s\r\n", url)
			metadata += fmt.Sprintf("Comment: %s\r\n", comment)
			metadata += g.formatHashes(hashes)

			g.updateStatusAsync("Signing metadata...")

			sig, algo, err := g.signDataInternal([]byte(g.pinEntry.Text), []byte(metadata))
			if err != nil {
				g.showErrorAsync("Signing failed: " + err.Error())
				return
			}

			result := metadata
			result += "-----BEGIN YUBISIGNER " + algo + " SIGNATURE-----\r\n"
			result += formatSignatureRFC(sig)
			result += "-----END YUBISIGNER " + algo + " SIGNATURE-----\r\n"

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

// onVerifyClick handles the Verify button click
func (g *GUI) onVerifyClick() {
	g.signingMode = false

	if g.currentFile == "" {
		g.selectFile(func() {
			g.continueVerify()
		})
		return
	}
	g.continueVerify()
}

// continueVerify continues the verification process after file selection
func (g *GUI) continueVerify() {
	if g.currentFile == "" {
		g.statusLabel.SetText("Error: No file selected")
		return
	}

	sigFile := g.currentFile + ".sig"
	sigData, err := os.ReadFile(sigFile)
	if err != nil {
		g.showErrorPopup("Signature not valid", nil)
		return
	}

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

	beginIdx := strings.Index(s, beginLine)
	endIdx := strings.Index(s, endLine)
	if beginIdx == -1 || endIdx == -1 || endIdx <= beginIdx {
		g.showErrorPopup("Signature not valid", nil)
		return
	}

	metadataStr := strings.TrimSpace(s[:beginIdx])
	sigBlock := s[beginIdx+len(beginLine) : endIdx]
	sigBlock = strings.TrimSpace(sigBlock)

	re := regexp.MustCompile(`[^a-fA-F0-9]`)
	sigHex := re.ReplaceAllString(sigBlock, "")

	fileInfo, err := os.Stat(g.currentFile)
	if err != nil {
		g.statusLabel.SetText("Error getting file info: " + err.Error())
		return
	}
	currentFileSize := fileInfo.Size()

	// STRICT HEADER VALIDATION
	expectedHeaders := []string{
		"Author:",
		"Signed at:",
		"Filename:",
		"File size:",
		"Email:",
		"Telefax:",
		"URL:",
		"Comment:",
	}

	metadataLines := strings.Split(metadataStr, "\r\n")
	for len(metadataLines) > 0 && metadataLines[len(metadataLines)-1] == "" {
		metadataLines = metadataLines[:len(metadataLines)-1]
	}

	if len(metadataLines) < len(expectedHeaders) {
		g.showErrorPopup("Signature not valid (missing headers)", nil)
		return
	}

	for i, expected := range expectedHeaders {
		if !strings.HasPrefix(metadataLines[i], expected) {
			g.showErrorPopup("Signature not valid (header mismatch)", nil)
			return
		}
	}

	expectedSize := int64(-1)
	sizeLine := metadataLines[3]
	parts := strings.SplitN(sizeLine, ": ", 2)
	if len(parts) == 2 {
		fmt.Sscanf(strings.TrimSpace(parts[1]), "%d bytes", &expectedSize)
	}

	if expectedSize != -1 && expectedSize != currentFileSize {
		g.showErrorPopup("Signature not valid", nil)
		return
	}

	hashLinesFromSig := metadataLines[len(expectedHeaders):]

	done := make(chan bool)

	g.statusLabel.SetText(fmt.Sprintf("Preparing to verify %s...", formatByteSize(int(currentFileSize))))

	if currentFileSize <= 1024*1024*1024 {
		g.progressBar.SetValue(0)
		g.progressBar.Show()
		g.progressLabel.SetText("Loading file...")
		g.progressLabel.Show()
		g.statusLabel.SetText(fmt.Sprintf("Loading %s into RAM...", filepath.Base(g.currentFile)))

		go func() {
			defer func() { done <- true }()
			startTime := time.Now()

			file, err := os.Open(g.currentFile)
			if err != nil {
				g.showErrorAsync("Signature not valid")
				return
			}

			var data []byte
			buf := make([]byte, 32*1024*1024)
			bytesRead := int64(0)

			for {
				n, err := file.Read(buf)
				if n > 0 {
					data = append(data, buf[:n]...)
					bytesRead += int64(n)
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

			fyne.Do(func() {
				g.progressLabel.SetText("Calculating hashes...")
			})

			expectedHashes := g.calculateHashesRAM(data)
			expectedHashLines := strings.Split(g.formatHashes(expectedHashes), "\r\n")

			for len(expectedHashLines) > 0 && expectedHashLines[len(expectedHashLines)-1] == "" {
				expectedHashLines = expectedHashLines[:len(expectedHashLines)-1]
			}

			if len(hashLinesFromSig) != len(expectedHashLines) {
				g.showErrorAsync("Signature not valid (hash count mismatch)")
				return
			}

			hashValid := true
			for i, expectedLine := range expectedHashLines {
				if i >= len(hashLinesFromSig) {
					hashValid = false
					break
				}
				if hashLinesFromSig[i] != expectedLine {
					hashValid = false
					break
				}
			}

			if !hashValid {
				g.showErrorAsync("Signature not valid")
				return
			}

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
	} else {
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

			expectedHashLines := strings.Split(g.formatHashes(expectedHashes), "\r\n")
			for len(expectedHashLines) > 0 && expectedHashLines[len(expectedHashLines)-1] == "" {
				expectedHashLines = expectedHashLines[:len(expectedHashLines)-1]
			}

			if len(hashLinesFromSig) != len(expectedHashLines) {
				g.showErrorAsync("Signature not valid (hash count mismatch)")
				return
			}

			hashValid := true
			for i, expectedLine := range expectedHashLines {
				if i >= len(hashLinesFromSig) {
					hashValid = false
					break
				}
				if hashLinesFromSig[i] != expectedLine {
					hashValid = false
					break
				}
			}

			if !hashValid {
				g.showErrorAsync("Signature not valid")
				return
			}

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

	go func() {
		<-done
	}()
}

// showErrorPopup shows simple error popup dialog
func (g *GUI) showErrorPopup(message string, publicKeyBytes []byte) {
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
	d.SetOnClosed(func() {
		fyne.Do(func() {
			g.statusLabel.SetText("Ready")
		})
	})
	d.Show()
}

// showSuccessPopupWithIdenticon shows the identicon on successful verification
func (g *GUI) showSuccessPopupWithIdenticon(hash []byte) {
	fyne.Do(func() {
		g.progressBar.Hide()
		g.progressLabel.Hide()
	})

	identicon := NewClassicIdenticon(hash)
	img := identicon.Generate()
	fyneImg := canvas.NewImageFromImage(img)
	fyneImg.FillMode = canvas.ImageFillContain
	fyneImg.SetMinSize(fyne.NewSize(128, 128))

	successLabel := widget.NewLabel("Verification Successful")
	successLabel.Alignment = fyne.TextAlignCenter

	content := container.NewVBox(
		container.NewCenter(fyneImg),
		container.NewCenter(successLabel),
	)

	d := dialog.NewCustom("", "OK", content, g.window)
	d.SetOnClosed(func() {
		fyne.Do(func() {
			g.statusLabel.SetText("Ready")
		})
	})
	d.Show()
}

// calculateHashesRAM calculates all hashes for files that fit in RAM
func (g *GUI) calculateHashesRAM(data []byte) map[string]string {
	hashes := make(map[string]string)

	gostHasher := gost34112012256.New()
	gostHasher.Write(data)
	hashes["Streebog-256"] = hex.EncodeToString(gostHasher.Sum(nil))

	ripemdHasher := ripemd.New256()
	ripemdHasher.Write(data)
	hashes["RIPEMD-256"] = hex.EncodeToString(ripemdHasher.Sum(nil))

	sha256Hash := sha256.Sum256(data)
	hashes["SHA-256"] = hex.EncodeToString(sha256Hash[:])

	sm3Hasher := sm3.New()
	sm3Hasher.Write(data)
	hashes["SM3"] = hex.EncodeToString(sm3Hasher.Sum(nil))

	return hashes
}

// calculateFileHashesOptimized calculates hashes for very large files with progress
func (g *GUI) calculateFileHashesOptimized(filePath string) (map[string]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfo, _ := os.Stat(filePath)
	totalSize := fileInfo.Size()

	bufSize := 32 * 1024 * 1024
	if totalSize > 4*1024*1024*1024 {
		bufSize = 64 * 1024 * 1024
	}

	buf := make([]byte, bufSize)

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
			gostHasher.Write(buf[:n])
			ripemdHasher.Write(buf[:n])
			sha256Hasher.Write(buf[:n])
			sm3Hasher.Write(buf[:n])

			bytesProcessed += int64(n)

			progress := int(float64(bytesProcessed) / float64(totalSize) * 100)
			if progress > lastProgress {
				lastProgress = progress
				elapsed := time.Since(startTime).Seconds()
				speed := float64(bytesProcessed) / elapsed / 1024 / 1024

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
					if progress%10 == 0 {
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
	keys := make([]string, 0, len(hashes))
	for k := range hashes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	maxLen := 0
	for _, k := range keys {
		if len(k) > maxLen {
			maxLen = len(k)
		}
	}

	var result strings.Builder
	for _, k := range keys {
		paddedKey := fmt.Sprintf("%*s", maxLen, k)
		result.WriteString(fmt.Sprintf("%s: %s\r\n", paddedKey, hashes[k]))
	}
	return result.String()
}

// signDataInternal performs the actual signing operation with YubiKey
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

	if ed25519PubKey, ok := cert.PublicKey.(ed25519.PublicKey); ok {
		hash := sha256.Sum256(data)
		return g.signEd25519Data(string(pin), hash[:], ed25519PubKey, yk)
	}

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

// onClear resets all UI fields to default state
func (g *GUI) onClear() {
	g.authorEntry.SetText("")
	g.emailEntry.SetText("")
	g.urlEntry.SetText("")
	g.telefaxEntry.SetText("")
	g.commentEntry.SetText("")
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

// safePad pads or truncates byte slice to specified size
func safePad(b []byte, size int) []byte {
	if len(b) > size {
		return b[len(b)-size:]
	}
	return append(make([]byte, size-len(b)), b...)
}

// formatSignatureRFC formats signature in RFC-compliant format with line breaks
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

// formatByteSize converts bytes to human-readable format
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

// stripLeadingZeros removes leading zero bytes from byte slice
func stripLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	return b[i:]
}

// extractPublicKeyDisplayBytes extracts public key bytes for identicon generation
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

// openYubiKey opens YubiKey at specified index
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

// ClassicIdenticon generates visual identicons from hash data
type ClassicIdenticon struct {
	source []byte
	size   int
}

// NewClassicIdenticon creates a new identicon generator
func NewClassicIdenticon(source []byte) *ClassicIdenticon {
	return &ClassicIdenticon{
		source: source,
		size:   256,
	}
}

// getBit retrieves a specific bit from the source data
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

// foreground returns the primary color for the identicon
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

// secondaryColor returns the secondary color for the identicon
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

// generatePixelPattern generates the pixel pattern for the identicon
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

// drawRect draws a filled rectangle on the image
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

// Generate creates the final identicon image
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
