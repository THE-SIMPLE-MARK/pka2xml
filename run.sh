# check if the docker image is already built
if [ "$(docker images -q pka2xml:1.0.0)" = "" ]; then
  # if not built, build the Docker image
  docker build -t pka2xml:1.0.0 .
fi

# run the Docker container
docker run -it pka2xml:1.0.0

docker build -t pka2xml:1.0.0 . && docker run -it pka2xml:1.0.0