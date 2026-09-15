// SPDX-License-Identifier: GPL-3.0-or-later

// Package unframeo is the repository root. It holds only the protobuf code-generation
// directives; there is no library code here (see internal/... and cmd/unframeo).
//
// Run "go generate ./..." to regenerate. Requires protoc (apt install
// protobuf-compiler) and protoc-gen-go (go install
// google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12). The generated .pb.go files
// are checked in, so an ordinary build needs neither tool.
package unframeo

//go:generate protoc --proto_path=internal/sdg/control --go_out=. --go_opt=module=github.com/borje/unframeo internal/sdg/control/control.proto
//go:generate protoc --proto_path=internal/frameo/pb --go_out=. --go_opt=module=github.com/borje/unframeo internal/frameo/pb/frameo.proto internal/frameo/pb/remote_manage.proto
