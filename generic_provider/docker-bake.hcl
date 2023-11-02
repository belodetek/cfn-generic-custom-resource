# https://docs.docker.com/build/bake/file-definition/
target "default" {
  platforms = [
    "linux/amd64",
    "linux/arm64"
  ]
}
