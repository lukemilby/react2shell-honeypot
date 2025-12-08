# react2shell-honeypot

Surprise its a honeypot for react2shell...

### Run

```shell  
go run main.go
```

### Docker

```shell
docker build -t react2shell-honeypot .
```

```shell
# -p HostPort:ContainerPort
docker run -d \
  --name react2shell-honeypot \
  -p 80:80 \
  -v $(pwd)/logs:/var/log/react2shell-honeypot \
  react2shell-honeypot


```

### logs

```shell
docker logs -f react2shell-honeypot
```

#### Kill docker container

```shell
docker kill react2shell-honeypot
```

#### Remove docker container

```shell
docker rm react2shell-honeypot
```
