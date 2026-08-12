package clicore

import "testing"

func TestContentClassForNameAndTypePreviewTypes(t *testing.T) {
	tests := []struct {
		name        string
		fileName    string
		contentType string
		want        string
	}{
		{"png extension", "photo.png", "application/octet-stream", "image"},
		{"jpeg mime", "photo.bin", "image/jpeg", "image"},
		{"webp extension", "photo.webp", "", "image"},
		{"pdf extension", "report.pdf", "application/octet-stream", "pdf"},
		{"pdf mime", "report.bin", "application/pdf", "pdf"},
		{"svg extension stays binary", "icon.svg", "application/octet-stream", "binary"},
		{"svg mime stays binary", "icon.bin", "image/svg+xml", "binary"},
		{"log extension (empty mime)", "app.log", "", "log"},
		{"log extension (octet-stream)", "server.log", "application/octet-stream", "log"},
		{"log mime", "trace.bin", "text/x-log", "log"},
		{"csv extension (empty mime)", "data.csv", "", "csv"},
		{"json extension (empty mime)", "data.json", "", "json"},
		{"txt extension (empty mime)", "notes.txt", "", "text"},
		{"go source", "main.go", "", "text"},
		{"python source", "app.py", "application/octet-stream", "text"},
		{"typescript source", "index.ts", "", "text"},
		{"shell script", "deploy.sh", "", "text"},
		{"html markup", "page.html", "", "text"},
		{"toml config", "config.toml", "", "text"},
		{"terraform", "main.tf", "", "text"},
		{"bare dotfile", ".gitignore", "", "text"},
		{"extensionless Dockerfile", "Dockerfile", "", "text"},
		{"extensionless Makefile", "Makefile", "", "text"},
		{"jsonl -> json", "events.jsonl", "", "json"},
		{"geojson -> json", "shape.geojson", "", "json"},
		{"unknown binary stays binary", "photo.rawbin", "application/octet-stream", "binary"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContentClassForNameAndType(tt.fileName, tt.contentType); got != tt.want {
				t.Fatalf("ContentClassForNameAndType() = %q, want %q", got, tt.want)
			}
		})
	}
}
