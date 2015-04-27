package gotiscrape

import "regexp"

var md5 = regexp.MustCompile("\\b[0-9a-fA-F]{32}\\b")
var sha1 = regexp.MustCompile("\\b[.0-9a-fA-F]{40}\\b")
var sha2 = regexp.MustCompile("\\b[0-9a-fA-F]{64}\\b")
var ipv4 = regexp.MustCompile("\\b([0-2]?[0-9]?[0-9])\\.([0-2]?[0-9]?[0-9])" +
	"\\.([0-2]?[0-9]?[0-9])\\.([0-2]?[0-9]?[0-9])\\b")
var email = regexp.MustCompile("\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+" +
	"\\.[a-zA-Z]{2,4}\\b")
var fqdn = regexp.MustCompile("\\b([a-zA-Z0-9\\.\\-]+" +
	"\\.[a-zA-Z0-9\\.\\-]+)\\b")

var allposipv6 = regexp.MustCompile("\\b[a-f0-9:.]+\\b")
