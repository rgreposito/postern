terraform {
  required_version = ">= 1.6.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.32"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

variable "namespace" {
  type    = string
  default = "postern"
}

variable "image" {
  type    = string
  default = "ghcr.io/rgreposito/postern:0.1.0"
}

resource "kubernetes_namespace_v1" "this" {
  metadata {
    name = var.namespace
  }
}

# The ticket key is generated here because I got tired of watching
# people commit one. Rotate by tainting this resource.
resource "random_id" "ticket" {
  byte_length = 32
}

resource "kubernetes_secret_v1" "ticket" {
  metadata {
    name      = "postern-ticket"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
  }
  data = {
    key = random_id.ticket.b64_std
  }
}

output "namespace" {
  value = kubernetes_namespace_v1.this.metadata[0].name
}
