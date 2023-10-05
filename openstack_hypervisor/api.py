# Copyright 2022 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json

from fastapi import FastAPI
from pydantic import BaseModel
from snaphelpers import Snap

from openstack_hypervisor import hooks, manage_guests, model

app = FastAPI()
snap = Snap()


MAPPING = {
    "identity": model.IdentityServiceConfig,
    "rabbitmq": model.RabbitMQConfig,
    "compute": model.ComputeConfig,
    "network": model.NetworkConfig,
    "node": model.NodeConfig,
    "logging": model.LoggingConfig,
    "telemetry": model.TelemetryConfig,
    "monitoring": model.MonitoringConfig,
}


@app.get("/")
async def root():
    """Handles requests to the root URL.

    :return:
    """
    return {"version": "0.1"}


@app.get("/health")
async def health():
    """Handle requests for health status.

    A dictionary is returned, the key 'ready' indicates whether the
    hypervisor is up and functional.
    """
    service_status = snap.services.list()
    health = {
        "ready": all([v._info.active for v in service_status.values()]),
        "service_detail": service_status,
    }
    return health


@app.get("/settings")
async def settings():
    """Handle requests for settings.

    :return:
    """
    data = dict()
    for key in MAPPING.keys():
        data[key] = snap.config.get(key)

    return data


@app.get("/settings/{section}")
async def section_settings(section: str):
    """Handles requests for settings.

    :return:
    """
    clazz = MAPPING.get(section, None)
    data = snap.config.get(section)
    if clazz:
        data = clazz(**data).dict(by_alias=True)
    return data


def _update_settings(section: str, config: BaseModel):
    """Updates the snap settings.

    :param section:
    :param config:
    :return:
    """
    # XXX(wolsen) this is a bit wonky, but we convert the config object to json
    #  and then parse the config object back into a dictionary in order to
    #  avoid any attempts to serialize a non-serializable object - which will
    #  happen in the snap.config.set code. Most notably, this happens because
    #  the data is typed (e.g. an IPv4Address is not serializable).
    data = json.loads(config.json(by_alias=True))
    snap.config.set({section: data})
    hooks.configure(snap)
    return MAPPING.get(section)(**snap.config.get(section)).dict(by_alias=True)


@app.patch("/settings/identity")
async def update_identity(config: model.IdentityServiceConfig):
    """Updates identity section settings."""
    return _update_settings("identity", config)


@app.patch("/settings/network")
async def update_network(config: model.NetworkConfig):
    """Updates network section settings."""
    return _update_settings("network", config)


@app.patch("/settings/rabbitmq")
async def update_rabbitmq(config: model.RabbitMQConfig):
    """Updates rabbitmq section settings."""
    return _update_settings("rabbitmq", config)


@app.patch("/settings/compute")
async def update_compute(config: model.ComputeConfig):
    """Updates compute section settings."""
    return _update_settings("compute", config)


@app.patch("/settings/node")
async def update_node(config: model.NodeConfig):
    """Updates node section settings."""
    return _update_settings("node", config)


@app.patch("/settings/logging")
async def update_logging(config: model.LoggingConfig):
    """Updates logging section settings."""
    return _update_settings("logging", config)


@app.patch("/settings/telemetry")
async def update_telemetry(config: model.TelemetryConfig):
    """Updates telemetry section settings."""
    return _update_settings("telemetry", config)


@app.patch("/settings/monitoring")
async def update_monitoring(config: model.MonitoringConfig):
    """Updates monitoring section settings."""
    return _update_settings("monitoring", config)


@app.post("/reset")
async def reset_config():
    """Reset all configs to default."""
    config = {k: (v() if callable(v) else v) for k, v in hooks.DEFAULT_CONFIG.items()}
    unset_keys = [k for k, v in config.items() if v == hooks.UNSET]
    snap.config.set(config)
    # Replace with snap.config.unset when https://github.com/albertodonato/snap-helpers/pull/9
    # lands
    snap.config._snapctl.config_unset(*unset_keys)
    hooks.configure(snap)
    manage_guests.delete_openstack_guests()
