package caddyadf

import (
	"net/http"
	"net/url"
	"regexp"
)

// RequestSanitizer is responsible for sanitizing request headers and query parameters.
type RequestSanitizer struct {
	headerRedactionList      []string
	queryParamRedactionList  []string
	headerRedactionRegex     []*regexp.Regexp
	queryParamRedactionRegex []*regexp.Regexp
}

// NewRequestSanitizer creates a new RequestSanitizer.
func NewRequestSanitizer(headerRedactionList []string, queryParamRedactionList []string) *RequestSanitizer {
	var headerRegex []*regexp.Regexp
	for _, pattern := range headerRedactionList {
		re, err := regexp.Compile(pattern)
		if err == nil {
			headerRegex = append(headerRegex, re)
		}
	}
	var queryRegex []*regexp.Regexp
	for _, pattern := range queryParamRedactionList {
		re, err := regexp.Compile(pattern)
		if err == nil {
			queryRegex = append(queryRegex, re)
		}
	}
	return &RequestSanitizer{
		headerRedactionList:      headerRedactionList,
		queryParamRedactionList:  queryParamRedactionList,
		headerRedactionRegex:     headerRegex,
		queryParamRedactionRegex: queryRegex,
	}
}

// sanitizeHeaders creates a sanitized copy of the headers, redacting sensitive ones
func (rs *RequestSanitizer) SanitizeHeaders(headers http.Header) http.Header {
	sanitized := make(http.Header)
	for key, values := range headers {
		redacted := false
		for _, re := range rs.headerRedactionRegex {
			if re.MatchString(key) {
				redacted = true
				break
			}
		}

		if redacted {
			sanitized[key] = []string{"REDACTED"}
		} else {
			sanitized[key] = values
		}
	}
	return sanitized
}

// sanitizeQueryParams creates a sanitized copy of the query parameters, redacting sensitive ones
func (rs *RequestSanitizer) SanitizeQueryParams(queryParams url.Values) url.Values {
	sanitized := make(url.Values)
	for key, values := range queryParams {
		redacted := false
		for _, re := range rs.queryParamRedactionRegex {
			if re.MatchString(key) {
				redacted = true
				break
			}
		}

		if redacted {
			sanitized[key] = []string{"REDACTED"}
		} else {
			sanitized[key] = values
		}
	}
	return sanitized
}

// AddHeaderRedactionPattern add a new header redaction pattern
func (rs *RequestSanitizer) AddHeaderRedactionPattern(pattern string) {
	rs.headerRedactionList = append(rs.headerRedactionList, pattern)
	re, err := regexp.Compile(pattern)
	if err == nil {
		rs.headerRedactionRegex = append(rs.headerRedactionRegex, re)
	}
}

// AddQueryParamRedactionPattern add a new header redaction pattern
func (rs *RequestSanitizer) AddQueryParamRedactionPattern(pattern string) {
	rs.queryParamRedactionList = append(rs.queryParamRedactionList, pattern)
	re, err := regexp.Compile(pattern)
	if err == nil {
		rs.queryParamRedactionRegex = append(rs.queryParamRedactionRegex, re)
	}
}
