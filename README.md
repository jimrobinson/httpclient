# httpclient

Simple wrapper around the standard go net/http library to add timeouts
to http requests.

## Installation:

This library is compatible with Go1.1.

```
go get github.com/jimrobinson/httpclient
```

### Usage:

Import the library as well as the standard go time and net/http
libraries:

```
import "github.com/jimrobinson/httpclient"
import "log"
import "net/http"
import "time"
```

Decide on a timeout for your client, and create a new *HttpClient to
dispatch your requests:

```go
timeout := time.Duration(1 * time.Second)
client := NewHttpClient(timeout)

req, err := http.NewRequest("GET", "http://example.org/", nil)
if err != nil {
	log.Fatal(err)
}

rsp, err := client.Do(req)
if err != nil {
	log.Fatal(err)
}
defer rsp.Body.Close()
```
