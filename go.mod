module github.com/nats-io/nats-server

go 1.18

replace github.com/nats-io/gnatsd => ./

require (
	github.com/nats-io/gnatsd v0.0.0-00010101000000-000000000000
	github.com/nats-io/go-nats v1.7.0
	github.com/nats-io/nuid v1.0.1-0.20180316223952-28b996b57a46
	golang.org/x/crypto v0.0.0-20210314154223-e6e6c4f2bb5b
	golang.org/x/sys v0.0.0-20201119102817-f84b799fce68
)

require (
	github.com/nats-io/nkeys v0.3.0 // indirect
	google.golang.org/protobuf v1.26.0-rc.1 // indirect
)
