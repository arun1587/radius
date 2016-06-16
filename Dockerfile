FROM golang:1.6.2

ENV PROJECT_PATH=/go/src/github.com/bronze1man/radius
ENV PATH=$PATH:$PROJECT_PATH/bin

# setup work directory
RUN mkdir -p $PROJECT_PATH
WORKDIR $PROJECT_PATH

# copy source code
COPY . $PROJECT_PATH

RUN go get github.com/brocaar/lorawan
# build
RUN go build -o $PROJECT_PATH/bin/radius main.go

CMD ["radius"]
