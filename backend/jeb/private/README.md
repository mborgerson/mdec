Files needed:
* jeb-client.cfg

For jeb you'll need to get a key first. It's free. To generate this you'll just want to start the jeb container and run:

	/opt/jeb/jeb_linux.sh -c --generate-key

Follow the EULA accept, go to key generation page on PNF website listed in output, enter license data and follow through to get product key.

Then copy out /opt/jeb/bin/jeb-client.cfg and put it in this directory.

```
# Comment out COPY jeb-client.cfg line in Dockerfile
# Build container
docker run -it -name jeb mdec_jeb /opt/jeb/jeb_linux.sh -c --generate-key
docker cp jeb:/opt/jeb/bin/jeb-client.cfg backend/jeb/private/
docker rm jeb
# Uncomment COPY jeb-client.cfg line
# Rebuild
```
