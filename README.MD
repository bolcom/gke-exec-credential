# gke-exec-credential

## What is it?
It is a small external exec provider for Kubernetes that delegates getting and refreshing the access token to the `gcloud` command-line tool.

## How to build
* Install Rust via [rustup](https://rustup.rs/).
* Clone this repo
* `cargo build --release`
* The binary is `target/release/gke-exec-credential`

## Installation
In your `~/.kube/config` file, set up your K8S context like so:

```yaml
- context:
    cluster: my-fancy-k8s-cluster
    namespace: default
    user: gke
```

Then, add the `gke` user like so:

```yaml
users:
- name: gke
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: /path/to/gke-exec-credential
```

In the folder where `gke-exec-credential` is located a file called `gke-exec-credential-cached` will be placed with the cached gcloud access token. It will be refreshed automatically.

## Details
The implementation is based on [this](https://github.com/jglick/gke-exec-credential) credential helper, but adds a simple cache to avoid having to refresh the token on every call. Normally `ExecCredentials` are also cached until the client process exits, but this is not really suitable for a command-line workflow where the process exits after every invocation.