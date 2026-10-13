# tzn-mqtt

Torizon Cloud <-> Torizon OS MQTT bridge. Runs on TorizonOS an dconnects to Torizon Cloud via MQTT to receives events. After parsing, forwards events to aktualizr or rac.
This is a reference implementation only and not what is deployed on
production devices.

```
┌───────┐       ┌──────────┐     ┌──────────┐
│       ◄───────┘ tzn-mqtt ◄─────┤   mqtt   │
│       ┌───────►          │     │          │
│       │       └──────────┘     └──────────┘
│       │                                    
│       │       ┌──────────┐                 
│       ├───────► aktualizr│                 
│ dbus  │       │          │                 
│       │       └──────────┘                 
│       │                                    
│       │       ┌──────────┐                 
│       ├───────►    rac   │                 
│       │       │          │                 
└───────┘       └──────────┘                 
```

## DBus Dependencies

`tzn-mqtt` depends on dbus APIs provided `aktualizr` and `rac`.