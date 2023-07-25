FROM golang:1.20 AS build

# Set the Current Working Directory inside the container
WORKDIR /tmp/shdoauth

# We want to populate the module cache based on the go.{mod,sum} files.
COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

# Unit tests
#RUN CGO_ENABLED=0 go test -v

# Build the Go app
RUN go build -o /tmp/shdoauth/out/shdoauth ./main

# Start fresh from a smaller image - nonroot user
FROM alpine:latest
RUN apk --no-cache add ca-certificates
RUN apk add --no-cache libc6-compat gcompat

# Create a group and user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app/

# Copy the Pre-built binary file from the previous stage
COPY templates/ templates/
COPY --from=build /tmp/shdoauth/out/shdoauth /app/shdoauth

# This container exposes port 9001 to the outside world
EXPOSE 9001

# Change the ownership of the /app directory to the nonroot user
RUN chown -R appuser:appgroup /app/* 
USER appuser

RUN ls -al /app

# Run the binary program produced by `go install`
CMD ["./shdoauth"]
