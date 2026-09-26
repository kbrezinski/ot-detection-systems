# Water treatment dataset v1

This directory holds the topology, device instances, protocol profiles, scenarios,
and metadata for one version of the water-treatment testbed dataset.

- `topology/` describes sites, subnets, links, routers, and switches.
- `device_instances/` assigns addresses and roles to reusable models from `devices/`; `initial_devices.yaml` contains the first proposed PLC/RTUs, sensor, MQTT broker, SCADA, historian, and HMI nodes.
- `protocol_profiles/` records protocol versions, endpoints, topics/register maps,
  and security settings.
- `scenarios/` describes normal operations and each experiment or attack run.
- `metadata/` records labels, capture points, timestamps, and run configuration.
- `captures/` is for generated PCAPs and other large outputs; its contents are
  excluded from Git.

Keep reusable device behavior and definitions under the top-level `devices/`
directory. A future dataset should get a new versioned directory under `datasets/`
with its own topology and device instances.
