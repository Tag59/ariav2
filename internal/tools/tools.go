// Package tools defines the Tool interface and the registry of adapters.
// Each adapter wraps one external tool (nmap, httpx, ffuf, nuclei, testssl,
// enum4linux-ng...) with typed+bounded params, sandboxed execution and a
// PARSED structured output. Implemented in a later step (registry + port_scan).
package tools
