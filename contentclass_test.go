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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContentClassForNameAndType(tt.fileName, tt.contentType); got != tt.want {
				t.Fatalf("ContentClassForNameAndType() = %q, want %q", got, tt.want)
			}
		})
	}
}
