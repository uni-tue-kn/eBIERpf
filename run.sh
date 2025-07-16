#!/bin/bash
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --iface lo --config config.json

