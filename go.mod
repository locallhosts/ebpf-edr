module github.com/portfolio/ebpf-edr

go 1.22.2

replace golang.org/x/sys => github.com/golang/sys v0.20.0

replace golang.org/x/exp => github.com/golang/exp v0.0.0-20230224173230-c95f2b4c22f2

require (
	github.com/cilium/ebpf v0.16.0
	github.com/prometheus/client_golang v1.19.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.48.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/sys v0.20.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

replace google.golang.org/protobuf => github.com/protocolbuffers/protobuf-go v1.33.0
