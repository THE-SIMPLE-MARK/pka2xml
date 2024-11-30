# check if the docker image is already built
if [ "$(docker images -q pka2xml:1.0.0)" = "" ]; then
  # if not built, build the Docker image
  docker build -t pka2xml:1.0.0 .
fi

# create a shared directory if it doesn't exist
mkdir -p shared

# expose the shared directory in the container under /workspace
docker run \
	-v $(pwd)/shared:/workspace/shared \
	-it pka2xml:1.0.0