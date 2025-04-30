### Docker build & run
```
docker build -t gateway-app .
```

```
docker run -d --name gateway -p 9000:9000 -e SPRING_PROFILES_ACTIVE=dev gateway-app
```
