package clicore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type CacheManifest map[string]CacheEntry

type CacheEntry struct {
	Path      string    `json:"path"`
	SizeBytes uint64    `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	FileName  string    `json:"file_name"`
	PulledAt  time.Time `json:"pulled_at"`
}

type UpdateCheckCache struct {
	LastCheckedAt time.Time `json:"last_checked_at"`
	LatestVersion string    `json:"latest_version,omitempty"`
}

func CacheBaseDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "share2us"), nil
}

func CacheObjectsDir() (string, error) {
	base, err := CacheBaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "objects"), nil
}

func CacheManifestPath() (string, error) {
	base, err := CacheBaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "manifest.json"), nil
}

func UpdateCheckCachePath() (string, error) {
	base, err := CacheBaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "update_check.json"), nil
}

type SourceRegistry map[string]SourceRegistryEntry

type SourceRegistryEntry struct {
	PublicID string `json:"public_id"`
	Link     string `json:"link"`
}

type ListIndexEntry struct {
	Serial   int    `json:"serial"`
	PublicID string `json:"public_id"`
	FileName string `json:"file_name"`
}

func SourceRegistryPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "share2us", "source_manifest.json"), nil
}

func ListIndexPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "share2us", "list_index.json"), nil
}

func LoadSourceRegistry() (SourceRegistry, error) {
	path, err := SourceRegistryPath()
	if err != nil {
		return nil, err
	}
	return LoadSourceRegistryAt(path)
}

func LoadSourceRegistryAt(path string) (SourceRegistry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return SourceRegistry{}, nil
		}
		return nil, err
	}
	var registry SourceRegistry
	if err := json.Unmarshal(raw, &registry); err != nil {
		return nil, fmt.Errorf("parse source registry: %w", err)
	}
	if registry == nil {
		registry = SourceRegistry{}
	}
	return registry, nil
}

func SaveSourceRegistry(registry SourceRegistry) error {
	path, err := SourceRegistryPath()
	if err != nil {
		return err
	}
	return SaveSourceRegistryAt(path, registry)
}

func SaveSourceRegistryAt(path string, registry SourceRegistry) error {
	if registry == nil {
		registry = SourceRegistry{}
	}
	raw, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".source-manifest-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Chmod(path, 0o600)
}

func LoadListIndex() ([]ListIndexEntry, error) {
	path, err := ListIndexPath()
	if err != nil {
		return nil, err
	}
	return LoadListIndexAt(path)
}

func LoadListIndexAt(path string) ([]ListIndexEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var entries []ListIndexEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parse list index: %w", err)
	}
	if entries == nil {
		entries = []ListIndexEntry{}
	}
	return entries, nil
}

func SaveListIndex(entries []ListIndexEntry) error {
	path, err := ListIndexPath()
	if err != nil {
		return err
	}
	return SaveListIndexAt(path, entries)
}

func SaveListIndexAt(path string, entries []ListIndexEntry) error {
	if entries == nil {
		entries = []ListIndexEntry{}
	}
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".list-index-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Chmod(path, 0o600)
}

func AddSourceRegistryEntry(registry SourceRegistry, absPath string, entry SourceRegistryEntry) SourceRegistry {
	if registry == nil {
		registry = SourceRegistry{}
	}
	registry[absPath] = entry
	return registry
}

func SourceRefForPath(path string) (string, string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	hash := sha256.Sum256([]byte(absPath))
	return hex.EncodeToString(hash[:]), absPath, nil
}

func LoadCacheManifest() (CacheManifest, error) {
	path, err := CacheManifestPath()
	if err != nil {
		return nil, err
	}
	return LoadCacheManifestAt(path)
}

func LoadCacheManifestAt(path string) (CacheManifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CacheManifest{}, nil
		}
		return nil, err
	}
	var manifest CacheManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("parse cache manifest: %w", err)
	}
	if manifest == nil {
		manifest = CacheManifest{}
	}
	return manifest, nil
}

func SaveCacheManifest(manifest CacheManifest) error {
	path, err := CacheManifestPath()
	if err != nil {
		return err
	}
	return SaveCacheManifestAt(path, manifest)
}

func SaveCacheManifestAt(path string, manifest CacheManifest) error {
	if manifest == nil {
		manifest = CacheManifest{}
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".manifest-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Chmod(path, 0o600)
}

func LoadUpdateCheckCache() (UpdateCheckCache, error) {
	path, err := UpdateCheckCachePath()
	if err != nil {
		return UpdateCheckCache{}, err
	}
	return LoadUpdateCheckCacheAt(path)
}

func LoadUpdateCheckCacheAt(path string) (UpdateCheckCache, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return UpdateCheckCache{}, nil
		}
		return UpdateCheckCache{}, err
	}
	var cache UpdateCheckCache
	if err := json.Unmarshal(raw, &cache); err != nil {
		return UpdateCheckCache{}, fmt.Errorf("parse update check cache: %w", err)
	}
	return cache, nil
}

func SaveUpdateCheckCache(cache UpdateCheckCache) error {
	path, err := UpdateCheckCachePath()
	if err != nil {
		return err
	}
	return SaveUpdateCheckCacheAt(path, cache)
}

func SaveUpdateCheckCacheAt(path string, cache UpdateCheckCache) error {
	raw, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".update-check-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Chmod(path, 0o600)
}

func AddCacheEntry(manifest CacheManifest, publicID string, entry CacheEntry) CacheManifest {
	if manifest == nil {
		manifest = CacheManifest{}
	}
	manifest[publicID] = entry
	return manifest
}

func RemoveCacheEntry(manifest CacheManifest, publicID string) CacheManifest {
	if manifest == nil {
		return CacheManifest{}
	}
	delete(manifest, publicID)
	return manifest
}

func CacheEntryIsLocal(entry CacheEntry) bool {
	if entry.Path == "" || entry.SHA256 == "" {
		return false
	}
	info, err := os.Stat(entry.Path)
	if err != nil || info.IsDir() {
		return false
	}
	if entry.SizeBytes != 0 && uint64(info.Size()) != entry.SizeBytes {
		return false
	}
	sum, err := FileSHA256(entry.Path)
	if err != nil {
		return false
	}
	return sum == entry.SHA256
}

func FileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
