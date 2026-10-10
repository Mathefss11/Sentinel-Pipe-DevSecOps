"""Session-scoped real infrastructure for the integration tests (see infrastructure.py)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from broker_diagnostics import diagnosed
from infrastructure import (
    POSTGRES_IMAGE,
    RABBITMQ_IMAGE,
    Broker,
    ControlPlane,
    new_password,
    provision_broker,
    provision_control_plane,
    purge_all,
)
from testcontainers.community.postgres import PostgresContainer
from testcontainers.community.rabbitmq import RabbitMqContainer


@pytest.fixture(scope="session")
def broker() -> Iterator[Broker]:
    container = RabbitMqContainer(
        RABBITMQ_IMAGE, username="sentinel-admin", password=new_password()
    )
    with diagnosed(container, "container start"):
        container.start()
    try:
        with diagnosed(container, "topology and user provisioning"):
            provisioned = provision_broker(container)
        yield provisioned
    finally:
        container.stop()


@pytest.fixture(scope="session")
def control_plane() -> Iterator[ControlPlane]:
    password = new_password()
    container = PostgresContainer(
        POSTGRES_IMAGE, username="sentinel", password=password, dbname="sentinelpipe", driver=None
    )
    container.start()
    try:
        yield provision_control_plane(container, "sentinel", password)
    finally:
        container.stop()


@pytest.fixture
def empty_queues(broker: Broker) -> None:
    purge_all(broker)
