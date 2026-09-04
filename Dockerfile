# Build
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/keydirectory ./cmd/keydirectory

# Run
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/keydirectory /keydirectory
EXPOSE 8092
USER nonroot:nonroot
ENTRYPOINT ["/keydirectory"]
