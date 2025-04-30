### Docker build & run
```
docker build -t gateway-app .
```

```
docker run -d --name gateway -p 9000:9000 -e SPRING_PROFILES_ACTIVE=dev gateway-app
```

### K8s
환경별 네임스페이스 생성
```
kubectl create namespace dev
kubectl create namespace prod
kubectl get namespaces
```

환경별 매니페스트 적용(명시 없으면 default 네임스페이스로 감)
```
kubectl apply -f manifests/ -n dev
```

```
kubectl get pods -n dev
kubectl get services -n dev
kubectl get configmaps -n dev
```

적용된 매니페스트 제거
```
kubectl delete services gateway -n dev
kubectl delete pods gateway -n dev
kubectl delete configmap gateway-config -n dev
```
