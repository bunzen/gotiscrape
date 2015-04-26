// Package gotiscrape provides simple utility functions to carve
// typically used as threat intelligence from a body of text.
package gotiscrape

import (
	"net"
	"strings"
)

// FindAll extracts all known patterns from a body of text and returns them
// in a map[string][]string. If you are only interested in specific body,
// you are adviced to use the function directly.
func FindAll(body string) map[string][]string {
	ret := make(map[string][]string)

	ret["md5"] = FindMd5(body)
	ret["sha1"] = FindSha1(body)
	ret["sha2"] = FindSha2(body)
	ret["ipv4"] = FindIPv4(body)
	ret["ipv6"] = FindIPv6(body)
	ret["email"] = FindEmail(body)
	ret["fqdn"] = FindFQDN(body)

	return ret
}

// FindMd5 extracts all md5 like hexdigest strings from a body of text and
// returns them as a string slice.
func FindMd5(body string) []string {
	return dedup(md5.FindAllString(body, -1))
}

// FindSha1 extracts all sha1 hexdigest like strings from a body of text and
// returns them as a string slice.
func FindSha1(body string) []string {
	return dedup(sha1.FindAllString(body, -1))
}

// FindSha2 extracts all sha256 hexdigest like strings from a body of text and
// returns them as a string slice.
func FindSha2(body string) []string {
	return dedup(sha2.FindAllString(body, -1))
}

// FindIPv4 extracts all IPv4 like strings from a body of text and
// returns them as a string slice.
func FindIPv4(body string) []string {
	return dedup(ipv4.FindAllString(body, -1))
}

// FindIPv6 extracts all IPv6 like strings from a body of text and
// returns them as a string slice.
func FindIPv6(body string) []string {

	// retrieve a string slice of all words (between word boundries)
	// that could possibly be a IPv6 string and validate them using
	// package net
	allpos := dedup(allposipv6.FindAllString(body, -1))

	var ret []string

	for _, posipv6 := range allpos {
		if ip := net.ParseIP(posipv6); ip != nil {
			// since ip is ok and we know that ParseIP will
			// return either an ipv4 OR an ipv6 adress and
			// .To4() doc say "If ip is not an IPv4 address, To4 returns nil"
			// we can assume that a .To4() returning nil will in effect mean
			// .IsIPv6() == true
			if ip.To4() == nil {
				ret = append(ret, posipv6)
			}
		}
	}

	return ret
}

// FindEmail extracts all email like strings from a body of text and
// returns them as a string slice.
func FindEmail(body string) []string {
	return dedup(email.FindAllString(body, -1))
}

// FindFQDN extracts all fqdn like strings from a body of text and returns them
// as a string slice. The finds are filtered against a predefined string slice
// of valid top-level domains (TLD) before return.
func FindFQDN(body string) []string {
	return endingInTLD(dedup(fqdn.FindAllString(body, -1)))
}

// dedup removes duplicates from a string slice of strings
func dedup(s []string) []string {
	t := make(map[string]bool)
	for _, e := range s {
		t[e] = true
	}
	var l []string
	for k := range t {
		l = append(l, k)
	}
	return l
}

// endingInTLD filters a string slice against a string slice of TLDs, only
// returning strings thats ends in a valid TLD
func endingInTLD(s []string) []string {
	t := make(map[string]bool)
	for _, e := range s {
		n := strings.Split(e, ".")
		tl := strings.ToTitle(n[len(n)-1])
		for _, tld := range tld {
			if tld == tl {
				t[e] = true
				break
			}
		}
	}
	var l []string
	for k := range t {
		l = append(l, k)
	}

	return l
}
