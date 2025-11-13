┌─────────────────────────────────────┐
                     │           React Dashboard            │
                     │     (SOC UI + Admin Interface)       │
                     └───────────────────┬──────────────────┘
                                         │
                                 REST / WebSocket
                                         │
                     ┌───────────────────▼──────────────────┐
                     │            API Gateway                │
                     │ (Authentication, Routing, Policies)   │
                     └───────┬───────────────┬──────────────┘
                             │               │
                             │               │
       ┌─────────────────────▼───┐     ┌─────▼───────────────────────┐
       │        Collector         │     │           Analyzer           │
       │  (Agents, endpoint data) │     │  Neural Threat Brain (AI/ML) │
       └─────────────┬───────────┘     └───────────┬─────────────────┘
                     │                             │
                     └───────────────┬─────────────┘
                                     ▼
                           Message Bus Layer
                  (Redis | RabbitMQ | Kafka — pluggable)
                                     │
        ┌────────────────────────────┴──────────────────────────┐
        │                   Report Service                       │
        │ (Alerting, incident reports, notification pipeline)   │
        └────────────────────────────┬──────────────────────────┘
                                     │
                                     ▼
                         Blockchain Audit Layer
              (Immutable events, signed logs, zero-trust trails)
