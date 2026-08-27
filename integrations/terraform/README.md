# Terraform provider — not built

A Terraform provider is a separate Go module built on
`hashicorp/terraform-plugin-framework`. That dependency is not available in this
build environment, and a provider that does not compile against the real
framework would be worse than none.

The API is ready for one. A provider would wrap:

| Terraform | SKM endpoint |
|---|---|
| `resource "skm_key"` | `POST /api/v1/keys`, `PATCH /api/v1/keys/{id}` |
| `resource "skm_target"` | `POST /api/v1/targets` |
| `resource "skm_assignment"` | `POST /api/v1/assignments` |
| `resource "skm_rotation_policy"` | `POST /api/v1/rotation-policies` |
| `data "skm_key"` | `GET /api/v1/keys?q=` |
| `data "skm_targets"` | `GET /api/v1/targets` |

One design note for whoever builds it: `skm_key` must not expose the private
half as an attribute. Terraform state is stored in plaintext by most backends,
so a private key in state is a private key on a bucket somewhere. Point a
consumer at the key instead, and let SKM deliver it.

Until then, `skmctl --json` works with Terraform's `external` data source:

```hcl
data "external" "deploy_key" {
  program = ["skmctl", "keys", "list", "--json"]
}
```
