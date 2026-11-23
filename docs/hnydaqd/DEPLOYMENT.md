# HNYDAQD Deployment Guide

This document describes how to deploy the HNYDAQD security layer on top of the
Onyx FOSS foundation.

## Prerequisites

- Docker 24+ and Docker Compose v2.
- A 64-character hex encryption key. Generate once:
  ```bash
  openssl rand -hex 32
