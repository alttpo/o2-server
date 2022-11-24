## build
FROM golang:1.19 AS build

WORKDIR /app

COPY ./go.mod ./
COPY ./go.sum ./
RUN go mod download

COPY . ./
RUN go build -o /o2-server

## deploy
FROM gcr.io/distroless/base-debian10

WORKDIR /

COPY --from=build /o2-server /o2-server

USER nonroot:nonroot

ENTRYPOINT ["/o2-server"]
