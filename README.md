# tzn-mqtt

device side MQTT <-> dbus bridge.

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
