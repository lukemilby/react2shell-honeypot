package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

type ResponseLog struct {
	Time    string              `json:"time"`
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Status  int                 `json:"status"`
	Size    int                 `json:"size"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"` // Be careful with large bodies!
}

type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func (rw *responseWriterWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriterWrapper) Write(b []byte) (int, error) {
	rw.body.Write(b)                  // Store a copy
	return rw.ResponseWriter.Write(b) // Write to the actual client
}

func jsonLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Initialize the wrapper
		wrapper := &responseWriterWrapper{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // Default to 200 if WriteHeader is never called
			body:           &bytes.Buffer{},
		}

		// Process the request using our wrapper
		next.ServeHTTP(wrapper, r)

		// Create the log entry
		entry := ResponseLog{
			Time:    time.Now().Format(time.RFC3339),
			Method:  r.Method,
			URL:     r.URL.String(),
			Status:  wrapper.statusCode,
			Size:    wrapper.body.Len(),
			Headers: r.Header,
			Body:    wrapper.body.String(),
		}

		// Marshal to JSON
		logJSON, err := json.Marshal(entry)
		if err != nil {
			slog.Error("Error encoding log: %v", err)
			return
		}

		// Print the JSON line
		slog.Info(string(logJSON))
	})
}

func main() {
	logDir := "/var/log/react2shell-honeypot"
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		err := os.MkdirAll(logDir, 0o755)
		if err != nil {
			slog.Error("Error: %s ", err)
		}
	}

	// Open the file
	file, err := os.OpenFile(logDir+"/app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		slog.Error("Error: %s", err)
	}
	defer file.Close()

	w := io.MultiWriter(os.Stdout, file)

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	logger := slog.New(slog.NewJSONHandler(w, opts))

	slog.SetDefault(logger)

	port := ":80"
	mux := http.NewServeMux()
	mux.HandleFunc("/", scannerHandler)

	loggedMux := jsonLoggerMiddleware(mux)

	fmt.Printf("🛡️  React2Shell/Next.js Target running on port %s\n", port)
	fmt.Println("Waiting for scanner signature...")
	fmt.Println("Logging to /var/logs/react2shell-honeypot/app.log")

	if err := http.ListenAndServe(port, loggedMux); err != nil {
		log.Fatal(err)
	}
}

func scannerHandler(w http.ResponseWriter, r *http.Request) {
	// 1. SIGNATURE DETECTION
	// The Python script hardcodes these specific headers.
	// We check for them to ensure we are responding to this specific tool.
	// Headers from script:
	// "X-Nextjs-Request-Id": "b5dce965"
	// "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9"

	// Read the body to determine which check is being performed
	bodyBytes, _ := io.ReadAll(r.Body)
	bodyStr := string(bodyBytes)

	fmt.Println("Body Payload")
	fmt.Println("---------------------------------------")
	fmt.Printf("%s", bodyStr)
	fmt.Println("---------------------------------------")

	isScanner := len(r.Header.Get("X-Nextjs-Request-Id")) > 0 || len(r.Header.Get("X-Nextjs-Html-Request-Id")) > 0

	if !isScanner {
		// If it's not the scanner, just return a generic 404 or 200
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Standard Generic Homepage"))

		return
	}

	// Handle Rustsploit
	if strings.Contains(bodyStr, "whoami") {
		fmt.Println("Rustsploit detected")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("root"))
		return
	}

	// 2. HANDLE RCE CHECK (CVE-2025-55182 / CVE-2025-66478)
	// The scanner sends a payload containing "41*271".
	// The scanner expects the server to execute this math (Result: 11111)
	// and return it in the 'X-Action-Redirect' header.
	if strings.Contains(bodyStr, "41*271") {
		fmt.Println("   ↳ Type: RCE Check Detected")
		fmt.Println("   ↳ Action: Emulating Vulnerable Redirect")

		// The Python script regex: re.search(r'.*/login\?a=11111.*', redirect_header)
		w.Header().Set("X-Action-Redirect", "/login?a=11111;307;")
		w.Header().Set("Content-Type", "text/x-component")

		// Status doesn't strictly matter for the RCE regex check, but 200 is standard
		w.WriteHeader(http.StatusOK)

		return
	}

	// 3. HANDLE SAFE CHECK (Side-channel)
	// The scanner looks for specific JSON in the request (usually "$1:aa:aa")
	// And expects a 500 Error containing 'E{"digest"' in the body.
	if strings.Contains(bodyStr, "$1:aa:aa") {
		fmt.Println("   ↳ Type: Safe Check Detected")
		fmt.Println("   ↳ Action: Emulating 500 Error Leak")

		// Ensure we don't send Netlify/Vercel headers (as per is_mitigated logic)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		// Python script check: if response.status_code != 500 or 'E{"digest"' not in response.text
		w.WriteHeader(http.StatusInternalServerError)

		// We include the required string 'E{"digest"'
		responseBody := `0:["$@1",["$@2",null]]
1:E{"digest":"NEXT_REDIRECT;push;/login?a=11111;307;"}`
		w.Write([]byte(responseBody))
		return
	}

	// Fallback if headers matched but body didn't match known payloads
	w.WriteHeader(http.StatusOK)
}
