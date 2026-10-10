"""RabbitMQ consumption of control-plane events (scan requests).

Messages are untrusted input. They are validated against the shared contracts in
``packages/contracts`` (bundled in :mod:`sentinel_worker.messaging.contracts`),
deduplicated through a durable receipt store, and acknowledged only after the receipt
is committed. No repository is cloned and no scanner is executed in this phase.
"""
