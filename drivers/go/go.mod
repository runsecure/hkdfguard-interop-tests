module github.com/runsecure/hkdfguard-interop-tests/drivers/go

go 1.27.1

toolchain go1.27.3

require (
	cloud.google.com/go/kms v1.36.1
	cloud.google.com/go/secretmanager v1.23.1
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.15.0
	github.com/aws/aws-sdk-go-v2/config v1.33.14
	github.com/aws/aws-sdk-go-v2/service/kms v1.62.3
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.50.9
	github.com/hashicorp/vault/api v1.23.0
	github.com/runsecure/hkdfguard-go v0.9.1
	github.com/runsecure/hkdfguard-go/cache/awssecretsmanager v0.9.1
	github.com/runsecure/hkdfguard-go/cache/azurekeyvault v0.9.1
	github.com/runsecure/hkdfguard-go/cache/filepersecret v0.9.1
	github.com/runsecure/hkdfguard-go/cache/googlesecretmanager v0.9.1
	github.com/runsecure/hkdfguard-go/cache/hashicorpvault v0.9.1
	github.com/runsecure/hkdfguard-go/cache/jsonsecretsfile v0.9.1
	github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 v0.9.1
	github.com/runsecure/hkdfguard-go/keywrapping/awskms v0.9.1
	github.com/runsecure/hkdfguard-go/keywrapping/azurekeyvault v0.9.1
	github.com/runsecure/hkdfguard-go/keywrapping/googlekms v0.9.1
	github.com/runsecure/hkdfguard-go/keywrapping/hashicorpvault v0.9.1
	github.com/runsecure/hkdfguard-go/keywrapping/nativev1 v0.9.1
	github.com/runsecure/hkdfguard-go/pipeline v0.9.1
	github.com/runsecure/hkdfguard-go/securefile v0.9.1
	golang.org/x/sys v0.49.0
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.24.2 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.3.1 // indirect
	cloud.google.com/go/compute/metadata v0.10.0 // indirect
	cloud.google.com/go/iam v1.15.1 // indirect
	cloud.google.com/go/longrunning v1.5.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.24.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.13.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys v1.5.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets v1.5.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal v1.2.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.10.1 // indirect
	github.com/aws/aws-sdk-go-v2 v1.47.6 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.14 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.12.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.39.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.7 // indirect
	github.com/aws/smithy-go v1.28.8 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.8 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/s2a-go v0.1.11 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.25 // indirect
	github.com/googleapis/gax-go/v2 v2.27.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.8 // indirect
	github.com/hashicorp/go-rootcerts v1.1.0 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.2.0 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-7 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.72.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.72.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	google.golang.org/api v0.311.0 // indirect
	google.golang.org/genproto v0.0.0-20261104224025-d1e00e9f33ab // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261104224025-d1e00e9f33ab // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261104224025-d1e00e9f33ab // indirect
	google.golang.org/grpc v1.85.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

// The develop matrix builds against sibling checkouts; drop these to test the published modules.
replace (
	github.com/runsecure/hkdfguard-go => ../../../hkdfguard-go
	github.com/runsecure/hkdfguard-go/cache/awssecretsmanager => ../../../hkdfguard-go/cache/awssecretsmanager
	github.com/runsecure/hkdfguard-go/cache/azurekeyvault => ../../../hkdfguard-go/cache/azurekeyvault
	github.com/runsecure/hkdfguard-go/cache/filepersecret => ../../../hkdfguard-go/cache/filepersecret
	github.com/runsecure/hkdfguard-go/cache/googlesecretmanager => ../../../hkdfguard-go/cache/googlesecretmanager
	github.com/runsecure/hkdfguard-go/cache/hashicorpvault => ../../../hkdfguard-go/cache/hashicorpvault
	github.com/runsecure/hkdfguard-go/cache/jsonsecretsfile => ../../../hkdfguard-go/cache/jsonsecretsfile
	github.com/runsecure/hkdfguard-go/cryptoprovider/aesgcm256 => ../../../hkdfguard-go/cryptoprovider/aesgcm256
	github.com/runsecure/hkdfguard-go/keywrapping/awskms => ../../../hkdfguard-go/keywrapping/awskms
	github.com/runsecure/hkdfguard-go/keywrapping/azurekeyvault => ../../../hkdfguard-go/keywrapping/azurekeyvault
	github.com/runsecure/hkdfguard-go/keywrapping/googlekms => ../../../hkdfguard-go/keywrapping/googlekms
	github.com/runsecure/hkdfguard-go/keywrapping/hashicorpvault => ../../../hkdfguard-go/keywrapping/hashicorpvault
	github.com/runsecure/hkdfguard-go/keywrapping/nativev1 => ../../../hkdfguard-go/keywrapping/nativev1
	github.com/runsecure/hkdfguard-go/pipeline => ../../../hkdfguard-go/pipeline
	github.com/runsecure/hkdfguard-go/securefile => ../../../hkdfguard-go/securefile
)
