# https://docs.docker.com/build/bake/file-definition/
target "default" {
  platforms = [
    "linux/amd64",
    "linux/arm64"
  ]
}

# https://docs.docker.com/build/bake/reference/#targetattest
# https://docs.docker.com/build/attestations/slsa-provenance/
target "amd64" {
  attest = [
    "type=provenance,disabled=true"
  ]
  platforms = [
    "linux/amd64"
  ]
}

target "arm64" {
  attest = [
    "type=provenance,disabled=true"
  ]
  platforms = [
    "linux/arm64"
  ]
}
