mdec
====

Explore multiple decompilers and compare their output with minimal effort. Upload binary, get decompilation.

![](screenshot.png)

Supported Decompilers
---------------------
* [angr](https://angr.io/)
* [Binary Ninja](https://binary.ninja/)
* [Ghidra](https://ghidra-sre.org/)
* [IDA](https://hex-rays.com/decompiler/)
* [Snowman](https://github.com/yegord/snowman)

**Note:** For IDA and Binary Ninja, you must provide license and binaries; other decompilers will be downloaded automatically.

Components
----------
* Each decompiler is a service that runs in its own container
* A frontend web service proxies requests to backend service

Install
-------
You'll need to add your proprietary packages in `backend/*/private`. Then just:
```
COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker compose build
```

Run
---
```
docker compose up
```

Point your browser at http://127.0.0.1.

API
---
You can also request decomp like:
```
curl -F 'file=@test.o' http://127.0.0.1/ida/decompile
```

