# WinEVTX Log Collector

This is a simple WinEVTX log collector script - that can be used to collect Windows Event Logs for Incident Response

#DESCRIPTION:
    Exports security-relevant Windows event logs and optional system artifacts
    (network config, processes, services, scheduled tasks) to a timestamped
    folder under C:\ForensicLogs\. Supports full collection or targeted
    collection of specific log channels.
#Usage: .\Collect-ForensicLogs.ps1
#Help: .\Collect-ForensicLogs.ps1 -h
