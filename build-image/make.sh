NAME=kube-router-build
docker run --rm --name=$NAME -w /go/src/gitlab.com/trojan295/kube-router -v $GOPATH:/go golang:1.8.3 "make" "$@"
