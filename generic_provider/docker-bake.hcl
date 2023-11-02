# https://docs.docker.com/build/bake/file-definition/
target "default" {
  platforms = [
    "linux/amd64",
    "linux/arm64"
  ]
}

target "amd64" {
  platforms = [
    "linux/amd64"
  ]
}

target "arm64" {
  platforms = [
    "linux/arm64"
  ]
}
