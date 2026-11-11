# Seed KB

One YAML file per device model. Generic device knowledge only: never MACs, serials, IPs or names.

```yaml
make: DIRECTV
model: HR34
device_type: set-top-box
match:            # any rule hit => auto-identified
  ssdp_model: [HR34]
  http_title: []
  mdns_model: []
firmware_seen: []
notes: ""
```

Entries confirmed in the wizard land in `~/.local/share/homesentry/kb/`; promote the good
ones here by copying them in.
