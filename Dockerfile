FROM golang:1.25.6-trixie
ARG BPF2GO_VERSION=v0.17.1
ARG LLVM_VERSION=19

WORKDIR /dashdns/
COPY . .

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y --no-install-recommends \
    clang-${LLVM_VERSION} \
    llvm-${LLVM_VERSION} \
    libbpf-dev \
    libelf-dev \
    linux-libc-dev \
    make \
    gcc \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/bin/clang-${LLVM_VERSION} /usr/bin/clang && \
    ln -sf /usr/bin/llvm-strip-${LLVM_VERSION} /usr/bin/llvm-strip


RUN if [ "$(uname -m)" = "x86_64" ]; then \
        ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
        ln -sf /usr/include/x86_64-linux-gnu/asm-generic /usr/include/asm-generic; \
    elif [ "$(uname -m)" = "aarch64" ]; then \
        ln -sf /usr/include/aarch64-linux-gnu/asm /usr/include/asm && \
        ln -sf /usr/include/aarch64-linux-gnu/asm-generic /usr/include/asm-generic; \
    fi

ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:/usr/local/go/bin:${PATH}"

RUN go install github.com/cilium/ebpf/cmd/bpf2go@${BPF2GO_VERSION}


RUN go mod tidy
RUN go generate
RUN go build -o dnsd
