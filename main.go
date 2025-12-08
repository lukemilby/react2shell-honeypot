package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	logDir := "/var/log/react2shell-honeypot"
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		err := os.MkdirAll(logDir, 0o755)
		if err != nil {
			log.Fatalf("Erorr: %s ", err)
		}
	}

	// Open the file
	file, err := os.OpenFile(logDir+"/app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	log.SetOutput(file)

	port := ":80"
	http.HandleFunc("/", scannerHandler)

	fmt.Printf("🛡️  React2Shell/Next.js Target running on port %s\n", port)
	fmt.Println("Waiting for scanner signature...")
	if err := http.ListenAndServe(port, nil); err != nil {
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
	isScanner := len(r.Header.Get("X-Nextjs-Request-Id")) > 0 || len(r.Header.Get("X-Nextjs-Html-Request-Id")) > 0

	if !isScanner {
		// If it's not the scanner, just return a generic 404 or 200
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Standard Generic Homepage"))
		return
	}

	// Read the body to determine which check is being performed
	bodyBytes, _ := io.ReadAll(r.Body)
	bodyStr := string(bodyBytes)

	log.Printf("⚠️  Scanner Detected from %s", r.RemoteAddr)

	log.Printf("Body Payload\n %s", bodyStr)

	// 2. HANDLE RCE CHECK (CVE-2025-55182 / CVE-2025-66478)
	// The scanner sends a payload containing "41*271".
	// The scanner expects the server to execute this math (Result: 11111)
	// and return it in the 'X-Action-Redirect' header.
	if strings.Contains(bodyStr, "41*271") {
		log.Println("   ↳ Type: RCE Check Detected")
		log.Println("   ↳ Action: Emulating Vulnerable Redirect")

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
		log.Println("   ↳ Type: Safe Check Detected")
		log.Println("   ↳ Action: Emulating 500 Error Leak")

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
