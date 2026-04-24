locals {
  cfg = yamldecode(file("${path.module}/config.yaml"))
}
