package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"frameo/internal/frameo/frameotest"
)

// photoServer serves one photo. What it says the photo is, and what it hands
// over, are set separately from what the URL calls it, since the three
// disagreeing is the case worth testing.
type photoServer struct {
	contentType  string
	lastModified string
	body         []byte
}

// serve brings the server up at urlPath and returns the URL of the photo.
func (p *photoServer) serve(t *testing.T, urlPath string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(urlPath, func(w http.ResponseWriter, r *http.Request) {
		if p.contentType != "" {
			w.Header().Set("Content-Type", p.contentType)
		}
		if p.lastModified != "" {
			w.Header().Set("Last-Modified", p.lastModified)
		}
		w.Write(p.body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL + urlPath
}

// servePhoto is the ordinary case: a JPEG, served as one.
func servePhoto(t *testing.T, urlPath string, data []byte) string {
	t.Helper()
	return (&photoServer{contentType: "image/jpeg", body: data}).serve(t, urlPath)
}

// pairedFrame brings up a fake frame and pairs with it.
func pairedFrame(t *testing.T) (*frameotest.Frame, string) {
	t.Helper()
	withConfig(t)
	frame := frameotest.New()
	server, code := startFakeFrame(t, frame)
	if _, err := runCLI(t, "-server", server, "pair", code); err != nil {
		t.Fatal(err)
	}
	return frame, server
}

func TestSendFromAURL(t *testing.T) {
	frame, server := pairedFrame(t)

	want := jpegBytes(40000, 7)
	photoURL := servePhoto(t, "/holiday.jpg", want)

	out, err := runCLI(t, "-server", server, "send", photoURL)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	// The photo passes through a temporary file, which is this program's own
	// business; what was asked for is the URL.
	if !strings.Contains(out, photoURL) {
		t.Errorf("send output does not name the URL:\n%s", out)
	}

	photos := frame.Photos()
	if len(photos) != 1 {
		t.Fatalf("the frame holds %d photos, want 1", len(photos))
	}
	if !bytes.Equal(photos[0].Data, want) {
		t.Error("the frame received different bytes")
	}
	if got := photos[0].Media.GetFileExtension(); got != "jpg" {
		t.Errorf("the frame filed the photo as %q, want jpg", got)
	}
}

// Files and URLs mix freely in one batch.
func TestSendMixesFilesAndURLs(t *testing.T) {
	frame, server := pairedFrame(t)

	onDisk := filepath.Join(t.TempDir(), "local.jpg")
	if err := os.WriteFile(onDisk, jpegBytes(5000, 1), 0o600); err != nil {
		t.Fatal(err)
	}
	// The same file name at both ends, which is what one shared download
	// directory would have collided on.
	first := servePhoto(t, "/a/photo.jpg", jpegBytes(6000, 2))
	second := servePhoto(t, "/b/photo.jpg", jpegBytes(7000, 3))

	out, err := runCLI(t, "-server", server, "send", onDisk, first, second)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := strings.Count(out, "Sent"); got != 3 {
		t.Errorf("reported %d sends, want 3:\n%s", got, out)
	}
	photos := frame.Photos()
	if len(photos) != 3 {
		t.Fatalf("the frame holds %d photos, want 3", len(photos))
	}
	for i, want := range []int{5000, 6000, 7000} {
		if got := len(photos[i].Data); got != want {
			t.Errorf("photo %d is %d bytes, want %d: the batch arrived out of order", i, got, want)
		}
	}
}

// What the photo actually is settles the format, over what either the URL or
// the server called it. A CDN that transcodes serves a URL ending .jpg as
// something else, and the frame must be told what it is being given.
func TestSendFilesAPhotoByWhatItIs(t *testing.T) {
	frame, server := pairedFrame(t)

	png := []byte("\x89PNG\r\n\x1a\n")
	png = append(png, bytes.Repeat([]byte{7}, 2000)...)
	photoURL := (&photoServer{contentType: "image/jpeg", body: png}).serve(t, "/holiday.jpg")

	if _, err := runCLI(t, "-server", server, "send", photoURL); err != nil {
		t.Fatalf("send: %v", err)
	}
	photos := frame.Photos()
	if len(photos) != 1 {
		t.Fatalf("the frame holds %d photos, want 1", len(photos))
	}
	if got := photos[0].Media.GetFileExtension(); got != "png" {
		t.Errorf("the frame filed the photo as %q, want png", got)
	}
}

// A photo from the web is dated by the far end, not by the moment it was
// fetched, or everything ever sent this way sorts to today on the frame.
func TestSendDatesAURLByTheServersTime(t *testing.T) {
	frame, server := pairedFrame(t)

	// 2019-07-04T11:22:33Z.
	const modified = "Thu, 04 Jul 2019 11:22:33 GMT"
	want := time.Date(2019, 7, 4, 11, 22, 33, 0, time.UTC).UnixMilli()
	photoURL := (&photoServer{
		contentType:  "image/jpeg",
		lastModified: modified,
		body:         jpegBytes(3000, 5),
	}).serve(t, "/holiday.jpg")

	if _, err := runCLI(t, "-server", server, "send", photoURL); err != nil {
		t.Fatalf("send: %v", err)
	}
	photos := frame.Photos()
	if len(photos) != 1 {
		t.Fatalf("the frame holds %d photos, want 1", len(photos))
	}
	if got := photos[0].Media.GetCaptureDate(); got != want {
		t.Errorf("capture date = %d, want %d", got, want)
	}
}

// A password in a URL must not be the thing this program writes to the
// terminal, or to whatever is capturing it.
func TestSendHidesAPasswordInAURL(t *testing.T) {
	frame, server := pairedFrame(t)

	photoURL := servePhoto(t, "/holiday.jpg", jpegBytes(3000, 6))
	u, err := url.Parse(photoURL)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("someone", "hunter2")

	out, err := runCLI(t, "-server", server, "send", u.String())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if strings.Contains(out, "hunter2") {
		t.Errorf("send output carries the password:\n%s", out)
	}
	if !strings.Contains(out, "someone") {
		t.Errorf("send output does not name the URL it was given:\n%s", out)
	}
	if len(frame.Photos()) != 1 {
		t.Error("the photo did not reach the frame")
	}
}

// A URL that does not answer is reported before a frame is connected to, for
// the same reason a missing file is: half a batch on the frame is worse than
// none of it.
func TestSendChecksURLsBeforeConnecting(t *testing.T) {
	withConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := runCLI(t, "-server", "127.0.0.1:1", "send", srv.URL+"/missing.jpg")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v, want it to report the server's answer", err)
	}
}

// The local files in a batch are checked before any URL in it is fetched, so
// a typo is not found only after a long download has been paid for.
func TestSendChecksFilesBeforeFetchingURLs(t *testing.T) {
	withConfig(t)
	var asked bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = true
		w.Header().Set("Content-Type", "image/jpeg")
		w.Write(jpegBytes(3000, 1))
	}))
	defer srv.Close()

	_, err := runCLI(t, "-server", "127.0.0.1:1", "send", srv.URL+"/a.jpg", "/nonexistent/b.jpg")
	if err == nil || !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("err = %v, want it to name the missing file", err)
	}
	if asked {
		t.Error("the URL was fetched even though an argument after it names no file")
	}
}

// Everything that can be settled about a file on disk without a frame is
// settled before one is connected to. Stat alone would pass all of these.
func TestSendChecksWhatAFileIs(t *testing.T) {
	withConfig(t)
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.jpg")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	unreadable := filepath.Join(dir, "locked.jpg")
	if err := os.WriteFile(unreadable, jpegBytes(2000, 1), 0o000); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct{ path, want string }{
		{dir, "directory"},
		{empty, "empty"},
		{unreadable, "permission denied"},
	} {
		_, err := runCLI(t, "-server", "127.0.0.1:1", "send", c.path)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("sending %s: err = %v, want it to mention %q", c.path, err, c.want)
		}
	}
}

// Linking to the page a photo appears on instead of to the photo is the easy
// mistake, and it would put a page of HTML on the frame as a picture.
func TestSendRefusesAWebPage(t *testing.T) {
	const page = "<html><body><img src=photo.jpg></body></html>"
	for _, contentType := range []string{
		"text/html; charset=utf-8",
		// A missing semicolon, which servers really do send. The header will
		// not parse, so only the bytes themselves catch this one.
		"text/html charset=utf-8",
		// And a server that says nothing at all.
		"",
	} {
		withConfig(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if contentType != "" {
				w.Header().Set("Content-Type", contentType)
			}
			fmt.Fprint(w, page)
		}))

		_, err := runCLI(t, "-server", "127.0.0.1:1", "send", srv.URL+"/gallery")
		if err == nil || !strings.Contains(err.Error(), "not an image") {
			t.Errorf("Content-Type %q: err = %v, want it to say the URL is not an image", contentType, err)
		}
		srv.Close()
	}
}

func TestSendRefusesAURLThatServesNothing(t *testing.T) {
	withConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
	}))
	defer srv.Close()

	_, err := runCLI(t, "-server", "127.0.0.1:1", "send", srv.URL+"/empty.jpg")
	if err == nil || !strings.Contains(err.Error(), "no data") {
		t.Errorf("err = %v, want it to say nothing was served", err)
	}
}

// Nothing downloaded outlives the command, whether it finished or not.
func TestSendRemovesWhatItDownloaded(t *testing.T) {
	_, server := pairedFrame(t)
	// TMPDIR is where the downloads land, so an empty one afterwards is the
	// whole of the answer.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	photoURL := servePhoto(t, "/holiday.jpg", jpegBytes(5000, 4))
	if _, err := runCLI(t, "-server", server, "send", photoURL); err != nil {
		t.Fatalf("send: %v", err)
	}
	// And after a batch that fails part way through, which leaves the first
	// download to be cleared up by the failure of the second.
	missing := strings.Replace(photoURL, "/holiday.jpg", "/gone.jpg", 1)
	if _, err := runCLI(t, "-server", server, "send", photoURL, missing); err == nil {
		t.Error("want an error for a URL the server does not serve")
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("%d downloads were left behind in %s", len(entries), tmp)
	}
}

func TestParseSource(t *testing.T) {
	for _, c := range []struct {
		in     string
		isURL  bool
		badURL bool
	}{
		{in: "https://example.com/a.jpg", isURL: true},
		{in: "http://example.com/a.jpg", isURL: true},
		// url.Parse lowercases the scheme, so this is a URL like any other.
		{in: "HTTP://example.com/a.jpg", isURL: true},
		{in: "photo.jpg"},
		{in: "./photo.jpg"},
		{in: "/home/someone/photo.jpg"},
		// A path may hold a colon, and a scheme this program does not fetch is
		// not a URL as far as send is concerned.
		{in: "odd:name.jpg"},
		{in: "file:///home/someone/photo.jpg"},
		// Meant as a URL and mistyped. Reporting these as files that do not
		// exist would send the reader looking for a file.
		{in: "http:/example.com/a.jpg", badURL: true},
		{in: "https://", badURL: true},
		{in: "http://[::1/a.jpg", badURL: true},
	} {
		u, err := parseSource(c.in)
		switch {
		case c.badURL:
			if err == nil {
				t.Errorf("parseSource(%q) = %v, want an error", c.in, u)
			}
		case err != nil:
			t.Errorf("parseSource(%q): %v", c.in, err)
		case (u != nil) != c.isURL:
			t.Errorf("parseSource(%q) gave URL %v, want a URL: %t", c.in, u, c.isURL)
		}
	}
}

func TestPhotoExtension(t *testing.T) {
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4}
	png := []byte("\x89PNG\r\n\x1a\n")
	// HEIC has no signature http.DetectContentType knows, so it stands for
	// every format the bytes cannot answer for.
	heic := []byte("\x00\x00\x00\x18ftypheic")

	for _, c := range []struct {
		head     []byte
		declared string
		url      string
		want     string
		why      string
	}{
		{jpeg, "image/jpeg", "https://example.com/a.jpg", "jpg", "all three agree"},
		// The bytes are the photo; the other two are names for it.
		{png, "image/jpeg", "https://example.com/a.jpg", "png", "a transcoding CDN"},
		{jpeg, "", "https://example.com/download?id=7", "jpg", "nothing but the bytes"},
		// Nothing in the bytes, so the server's word for it stands.
		{heic, "image/heic", "https://example.com/download?id=7", "heic", "the server said"},
		{heic, "application/octet-stream", "https://example.com/a.HEIC", "heic", "only the URL said"},
		{heic, "", "https://example.com/a.jpeg", "jpeg", "SendPhoto spells this jpg"},
		// An extension that does not name a picture is not the format: a photo
		// served by a script would otherwise be filed on the frame as a php.
		{heic, "", "https://example.com/img.php?id=7", "", "nothing said"},
		{heic, "", "https://example.com/", "", "nothing said"},
	} {
		u, err := url.Parse(c.url)
		if err != nil {
			t.Fatal(err)
		}
		if got := photoExtension(c.head, c.declared, u); got != c.want {
			t.Errorf("photoExtension(%q, %q) = %q, want %q (%s)", c.declared, c.url, got, c.want, c.why)
		}
	}
}

func TestMediaType(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"image/jpeg", "image/jpeg"},
		{"image/jpeg; charset=binary", "image/jpeg"},
		{"IMAGE/JPEG", "image/jpeg"},
		{"", ""},
		// Will not parse, so it comes back as it was written rather than as
		// nothing: it still says the body is a page.
		{"text/html charset=utf-8", "text/html charset=utf-8"},
	} {
		if got := mediaType(c.in); got != c.want {
			t.Errorf("mediaType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
