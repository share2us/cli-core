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
	case strings.HasSuffix(normalizedName, ".md"), strings.HasSuffix(normalizedName, ".markdown"):
		return "markdown"
	case strings.HasSuffix(normalizedName, ".yml"), strings.HasSuffix(normalizedName, ".yaml"):
		return "text"
	case strings.HasSuffix(normalizedName, ".log"):
		return "log"
	case strings.HasSuffix(normalizedName, ".csv"):
		return "csv"
	case strings.HasSuffix(normalizedName, ".json"):
		return "json"
	case strings.HasSuffix(normalizedName, ".txt"), strings.HasSuffix(normalizedName, ".text"):
		return "text"
	}

	// Broad text/code/config extension coverage (mirror of the server classifier):
	// all map to the text class so common source/config files aren't sent as binary.
	ext := filepath.Ext(normalizedName)
	if jsonFileExtensions[ext] {
		return "json"
	}
	if textFileExtensions[ext] || textFileBasenames[filepath.Base(normalizedName)] {
		return "text"
	}

	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if mediaType == "" {
		mediaType = strings.ToLower(mime.TypeByExtension(filepath.Ext(name)))
	}
	switch mediaType {
	case "text/plain":
		return "text"
	case "text/x-log", "application/log":
		return "log"
	case "text/yaml", "text/x-yaml", "application/x-yaml", "application/yaml":
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

// textFileExtensions are extensions classified as the plain text content class
// (Free-tier allowed). Keys include the leading dot; bare dotfiles (".gitignore")
// are keyed by their whole name. Mirror of the server classifier.
var textFileExtensions = map[string]bool{
	// programming source
	".go": true, ".py": true, ".pyw": true, ".pyi": true, ".rb": true, ".php": true, ".phtml": true,
	".pl": true, ".pm": true, ".lua": true, ".tcl": true, ".js": true, ".mjs": true, ".cjs": true,
	".jsx": true, ".ts": true, ".tsx": true, ".mts": true, ".cts": true, ".c": true, ".h": true,
	".cpp": true, ".cxx": true, ".cc": true, ".hpp": true, ".hxx": true, ".hh": true, ".cs": true,
	".m": true, ".mm": true, ".java": true, ".kt": true, ".kts": true, ".scala": true, ".groovy": true,
	".swift": true, ".rs": true, ".dart": true, ".r": true, ".jl": true, ".ex": true, ".exs": true,
	".erl": true, ".hrl": true, ".clj": true, ".cljs": true, ".cljc": true, ".edn": true, ".hs": true,
	".ml": true, ".mli": true, ".fs": true, ".fsx": true, ".fsi": true, ".vb": true, ".pas": true,
	".d": true, ".nim": true, ".zig": true, ".v": true, ".sql": true, ".vhd": true, ".vhdl": true,
	".sv": true, ".asm": true, ".s": true, ".lisp": true, ".el": true, ".scm": true, ".rkt": true,
	// shell / scripts
	".sh": true, ".bash": true, ".zsh": true, ".fish": true, ".ksh": true, ".ps1": true, ".psm1": true,
	".psd1": true, ".bat": true, ".cmd": true, ".awk": true, ".sed": true,
	// web / markup / style
	".html": true, ".htm": true, ".xhtml": true, ".css": true, ".scss": true, ".sass": true,
	".less": true, ".styl": true, ".vue": true, ".svelte": true, ".astro": true, ".xml": true,
	".xsl": true, ".xslt": true, ".rss": true, ".atom": true,
	// config / build / infra
	".toml": true, ".ini": true, ".cfg": true, ".conf": true, ".config": true, ".properties": true,
	".env": true, ".editorconfig": true, ".lock": true, ".tf": true, ".tfvars": true, ".hcl": true,
	".proto": true, ".graphql": true, ".gql": true, ".cmake": true, ".mk": true, ".gradle": true,
	".bazel": true, ".bzl": true, ".dockerfile": true, ".containerfile": true, ".npmrc": true,
	".nvmrc": true, ".prettierrc": true, ".eslintrc": true, ".babelrc": true,
	// docs / prose
	".rst": true, ".adoc": true, ".asciidoc": true, ".tex": true, ".ltx": true, ".org": true,
	".srt": true, ".vtt": true, ".diff": true, ".patch": true, ".ics": true, ".vcf": true, ".nfo": true,
	// data (text)
	".tsv": true, ".plist": true,
	// dotfiles
	".gitignore": true, ".gitattributes": true, ".dockerignore": true, ".npmignore": true,
}

// jsonFileExtensions are JSON-family extensions classified as the json class.
var jsonFileExtensions = map[string]bool{
	".jsonl": true, ".ndjson": true, ".json5": true, ".jsonc": true, ".geojson": true,
}

// textFileBasenames are well-known extensionless text files (matched on the full
// lowercased base name).
var textFileBasenames = map[string]bool{
	"dockerfile": true, "makefile": true, "gnumakefile": true, "rakefile": true, "gemfile": true,
	"procfile": true, "jenkinsfile": true, "vagrantfile": true, "brewfile": true, "license": true,
	"readme": true, "changelog": true, "authors": true, "notice": true, "copying": true, "todo": true,
}

func hasTarStem(name, suffix string) bool {
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	return strings.HasSuffix(strings.TrimSuffix(name, suffix), ".tar")
}
