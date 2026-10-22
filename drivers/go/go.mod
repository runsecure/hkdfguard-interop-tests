module github.com/runsecure/hkdfguard-interop-tests/drivers/go

go 1.27.1

require (
	github.com/runsecure/hkdfguard-go v0.9.0
	github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 v0.9.0
	github.com/runsecure/hkdfguard-go/keywrapping/nativev1 v0.9.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

// The develop matrix builds against sibling checkouts; drop these to test the published modules.
replace (
	github.com/runsecure/hkdfguard-go => ../../../hkdfguard-go
	github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 => ../../../hkdfguard-go/cryptoprovider/aesgcm256
	github.com/runsecure/hkdfguard-go/keywrapping/nativev1 => ../../../hkdfguard-go/keywrapping/nativev1
)
