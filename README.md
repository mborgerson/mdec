mdec
====

Explore multiple decompilers and compare their output with minimal effort. Upload binary, get decompilation.

![](screenshot.png)

Supported Decompilers
---------------------
* [angr](https://angr.io/)
* [Binary Ninja](https://binary.ninja/)
* [Ghidra](https://ghidra-sre.org/)
* [Hex-Rays](https://hex-rays.com/decompiler/)
* [JEB CE](https://www.pnfsoftware.com/jeb/community-edition)
* [r2dec](https://github.com/wargio/r2dec-js)
* [Reko](https://github.com/uxmal/reko)
* [RetDec](https://github.com/avast/retdec)
* [Snowman](https://github.com/yegord/snowman)

**Note:** For Hex-Rays and Binary Ninja, you must provide license and binaries; other decompilers will be downloaded automatically.

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

**Tip:** If you want to build only a few services, append the service names to the above command (e.g. frontend, angr, etc.)

Run
---
```
docker compose up
```

Point your browser at http://127.0.0.1.

**Tip:** If you want to start only a few services, append the service names to the above command (e.g. frontend, angr, etc.)

API
---
You can also request decomp like:
```
curl -F 'file=@test.o' http://127.0.0.1/hexrays/decompile
```

