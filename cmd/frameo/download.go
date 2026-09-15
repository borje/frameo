// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// source is one photo named on the command line, resolved to a file on disk.
type source struct {
	// name is what to call the photo in anything printed about it: the path,
	// or the URL. A photo fetched from the web reads back as the URL it was
	// asked for rather than as the temporary file it passed through.
	name string
	// path is the file to send.
	path string
	// extension is the format, where the file at path does not carry it in
	// its name. Empty leaves it to the path.
	extension string
	// taken is when the photo was last changed at the far end, where the
	// server said. Zero leaves the capture date to the file's own time.
	taken time.Time
}

// maxDownloadBytes caps what one run may fetch, across all the URLs in it. A
// link that turns out to address something other than a photo should cost a
// little time, not the disk: without a ceiling, a mistyped one pointing at an
// archive or a video stream would be followed to the end, and a batch of them
// would be followed to the end one after another.
const maxDownloadBytes = 256 << 20

// sniffLen is how much of a photo http.DetectContentType reads.
const sniffLen = 512

// resolveSources turns the arguments of send into files to read.
//
// Everything is settled before the caller connects to a frame, so an
// unreadable file or a URL that does not answer is reported straight away
// rather than part way through a batch with some of the photos already sent.
// The returned function removes whatever was downloaded and must be called
// even when this fails, since a failure part way through still leaves the
// earlier downloads behind.
func resolveSources(ctx context.Context, args []string) ([]source, func(), error) {
	nothing := func() {}
	sources := make([]source, len(args))
	urls := make([]*url.URL, len(args))
	// Every local file first, whatever order the arguments came in. The check
	// costs nothing, and a typo in a file name found only after a long
	// download has been paid for is found too late to save anything.
	for i, arg := range args {
		u, err := parseSource(arg)
		if err != nil {
			return nil, nothing, err
		}
		if u != nil {
			urls[i] = u
			continue
		}
		if err := checkPhotoFile(arg); err != nil {
			return nil, nothing, err
		}
		sources[i] = source{name: arg, path: arg}
	}

	var dir string
	cleanup := func() {
		if dir != "" {
			_ = os.RemoveAll(dir)
		}
	}
	budget := int64(maxDownloadBytes)
	for i, u := range urls {
		if u == nil {
			continue
		}
		if dir == "" {
			var err error
			if dir, err = os.MkdirTemp("", "frameo-"); err != nil {
				return nil, cleanup, err
			}
		}
		s, n, err := download(ctx, u, dir, budget)
		if err != nil {
			return nil, cleanup, err
		}
		budget -= n
		sources[i] = s
	}
	return sources, cleanup, nil
}

// parseSource decides whether an argument names a URL to fetch or a file to
// read, and returns the URL when it is one.
//
// An argument that begins as an http or https URL was meant as one, so a
// malformed one is reported as a bad URL rather than passed to the file
// branch. There it would come back as a file that does not exist, and send
// whoever typed it looking for a file instead of at the extra slash.
func parseSource(arg string) (*url.URL, error) {
	u, err := url.Parse(arg)
	if err != nil {
		if hasHTTPPrefix(arg) {
			return nil, fmt.Errorf("%s is not a URL that can be fetched: %w", arg, err)
		}
		return nil, nil
	}
	// Anything else is a path, including one that happens to hold a colon.
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%s names no host: a URL wants two slashes after the scheme", arg)
	}
	return u, nil
}

func hasHTTPPrefix(arg string) bool {
	lower := strings.ToLower(arg)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// checkPhotoFile is the pre-flight for a file on disk: everything that can be
// established without connecting to a frame, so that a batch fails before any
// of it has been sent rather than in the middle of it.
func checkPhotoFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("%s is a directory, not a photo", path)
	}
	if st.Size() == 0 {
		return fmt.Errorf("%s is empty", path)
	}
	// Stat says nothing about whether this process may read what it described,
	// and that answer is worth having now rather than after a frame has been
	// dialled and the photos before this one sent.
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return f.Close()
}

// download fetches one URL into a file under dir, and reports how many bytes
// it took so that the run's budget can be drawn down.
func download(ctx context.Context, u *url.URL, dir string, budget int64) (source, int64, error) {
	// What is printed about the URL, with any password in it hidden. net/http
	// redacts the same thing in the errors it raises; a URL that reaches the
	// terminal or a log through this program should not be the one place the
	// password survives.
	name := u.Redacted()
	fail := func(format string, a ...any) (source, int64, error) {
		return source{}, 0, fmt.Errorf(format, a...)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fail("%s: %w", name, err)
	}
	// Named, so that a server which turns away an unidentified client can see
	// what this is rather than only that it is not a browser.
	req.Header.Set("User-Agent", "frameo")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Already redacted, and it names the URL itself.
		return source{}, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fail("%s: the server answered %s", name, resp.Status)
	}
	// Linking to the page a photo appears on rather than to the photo itself
	// is the easy mistake to make, and it would put a page of HTML on the
	// frame as a picture. Nothing else is refused on the strength of the
	// content type: servers describe images as octet-stream often enough that
	// insisting on image/* would turn away photos that are perfectly good.
	declared := mediaType(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(declared, "text/") {
		return fail("%s served %s, not an image: link to the image itself", name, declared)
	}

	f, err := os.CreateTemp(dir, "photo-*")
	if err != nil {
		return source{}, 0, err
	}
	// One byte past what is left, so that a body which is exactly too long is
	// told apart from one that fits.
	var start head
	n, err := io.Copy(io.MultiWriter(f, &start), io.LimitReader(resp.Body, budget+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fail("%s: %w", name, err)
	}
	switch {
	case n == 0:
		return fail("%s returned no data", name)
	case n > budget:
		return fail("%s is over the %d byte limit on what one run may fetch", name, maxDownloadBytes)
	}

	// The same refusal again, now against the bytes rather than against what
	// the server called them. It is not redundant: a Content-Type the parser
	// cannot take apart tells us nothing, and a server that sends none at all
	// says nothing either, while a page of HTML looks like one whatever its
	// headers said.
	if sniffed := mediaType(http.DetectContentType(start.b)); strings.HasPrefix(sniffed, "text/") {
		return fail("%s served %s, not an image: link to the image itself", name, sniffed)
	}

	// The frame files a photo under a capture date, and for a file on disk
	// SendPhoto takes that from the modification time. Last-Modified is the
	// same answer from the far end. Without it the temporary file's own time
	// stands, which would say every photo from the web was taken at the moment
	// it was fetched.
	taken, _ := http.ParseTime(resp.Header.Get("Last-Modified"))

	return source{
		name: name,
		path: f.Name(),
		// resp.Request is the request that was finally answered, so a URL that
		// redirected is read for its extension where it ended up rather than
		// where it was typed.
		extension: photoExtension(start.b, declared, resp.Request.URL),
		taken:     taken,
	}, n, nil
}

// head collects the start of what is written through it, which is all
// http.DetectContentType looks at, and passes the rest along untouched.
type head struct{ b []byte }

func (h *head) Write(p []byte) (int, error) {
	if room := sniffLen - len(h.b); room > 0 {
		h.b = append(h.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// photoExtension works out what format a downloaded photo is in, most
// trustworthy answer first: what the bytes are, then what the server called
// them, then what the URL called them. An empty answer leaves it to SendPhoto,
// whose own default is jpg.
//
// The bytes lead because they are the only source that is not merely a name. A
// CDN that transcodes serves a URL ending .jpg as WebP; a photo served by a
// script sits at a URL like img.php that names no format at all, or names one
// that is not the photo's. They do not settle it alone, because the formats a
// frame takes are not all ones with a signature http.DetectContentType knows --
// HEIC among them -- and naming those is what the other two answers are for.
func photoExtension(head []byte, declared string, u *url.URL) string {
	if ext := photoTypes[mediaType(http.DetectContentType(head))]; ext != "" {
		return ext
	}
	if ext := photoTypes[declared]; ext != "" {
		return ext
	}
	// Only an extension that names a picture is taken from the URL, for the
	// img.php reason above: the frame would otherwise file the photo as a php.
	if ext := strings.ToLower(strings.TrimPrefix(path.Ext(u.Path), ".")); photoExtensions[ext] {
		return ext
	}
	return ""
}

// photoTypes maps the content types worth sending to a frame to the extension
// it files them under.
//
// The table is written out rather than taken from mime.ExtensionsByType, which
// answers from the host's own mime database: what a photo ends up filed as on
// the frame should not depend on which machine sent it.
var photoTypes = map[string]string{
	"image/jpeg": "jpg",
	"image/png":  "png",
	"image/gif":  "gif",
	"image/webp": "webp",
	"image/heic": "heic",
	"image/heif": "heif",
	"image/bmp":  "bmp",
}

// photoExtensions is the same set seen from the other end: what an extension
// on a URL has to be to be believed. Derived from photoTypes, so that adding a
// format to one cannot leave the other behind.
var photoExtensions = func() map[string]bool {
	// jpeg alongside jpg, which is the same format under its other spelling.
	// SendPhoto puts the name right on the way out.
	m := map[string]bool{"jpeg": true}
	for _, ext := range photoTypes {
		m[ext] = true
	}
	return m
}()

// mediaType is a content type without its parameters, lowercased.
//
// A header that will not parse is passed back as it was written rather than as
// nothing. What it says is still evidence, and a Content-Type of
// "text/html charset=utf-8" -- a missing semicolon, which servers really do
// send -- must not read as an image merely because the parser could not take
// it apart.
func mediaType(header string) string {
	if mt, _, err := mime.ParseMediaType(header); err == nil {
		return mt
	}
	return strings.ToLower(strings.TrimSpace(header))
}
