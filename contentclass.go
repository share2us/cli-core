package clicore

import (
	"mime"
	"path/filepath"
	"strings"
)

const ContentClassFolder = "folder"

func ContentClassForNameAndType(name, contentType string) string {
	normalizedName := strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.HasSuffix(normalizedName, ".tar.gz"), strings.HasSuffix(normalizedName, ".tgz"):
		return "targz"
	case strings.HasSuffix(normalizedName, ".tar.bz2"), strings.HasSuffix(normalizedName, ".tbz2"):
		return "tarbz2"
	case strings.HasSuffix(normalizedName, ".png"), strings.HasSuffix(normalizedName, ".jpg"), strings.HasSuffix(normalizedName, ".jpeg"), strings.HasSuffix(normalizedName, ".gif"), strings.HasSuffix(normalizedName, ".webp"):
		return "image"
	case strings.HasSuffix(normalizedName, ".pdf"):
		return "pdf"
	case strings.HasSuffix(normalizedName, ".svg"):
		return "binary"
	case strings.HasSuffix(normalizedName, ".zip"):
		return "zip"
	case strings.HasSuffix(normalizedName, ".7z"):
		return "7z"
	case strings.HasSuffix(normalizedName, ".tar"):
		return "tar"
	}

	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if mediaType == "" {
		mediaType = strings.ToLower(mime.TypeByExtension(filepath.Ext(name)))
	}
	switch mediaType {
	case "text/plain":
		return "text"
	case "text/csv":
		return "csv"
	case "application/json":
		return "json"
	case "text/markdown", "text/x-markdown":
		return "markdown"
	case "image/png", "image/jpeg", "image/gif", "image/webp":
		return "image"
	case "image/svg+xml":
		return "binary"
	case "application/pdf":
		return "pdf"
	case "application/zip", "application/x-zip-compressed":
		return "zip"
	case "application/x-7z-compressed":
		return "7z"
	case "application/x-tar":
		return "tar"
	case "application/gzip":
		if hasTarStem(normalizedName, ".gz") {
			return "targz"
		}
	case "application/x-bzip2":
		if hasTarStem(normalizedName, ".bz2") {
			return "tarbz2"
		}
	}
	return "binary"
}

func hasTarStem(name, suffix string) bool {
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	return strings.HasSuffix(strings.TrimSuffix(name, suffix), ".tar")
}
