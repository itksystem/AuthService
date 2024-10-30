echo  -- «апуск установки
minikube start --nodes 3

echo -- пометили меткой worker что ноды будут работать дл€ запуска на них подов с этой же меткой worker
kubectl label nodes minikube-m02 dedicated=worker
kubectl label nodes minikube-m03 dedicated=worker

echo -- —тавим Ingress-контроллер
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update
helm install ingress-nginx ingress-nginx/ingress-nginx --namespace ingress-nginx --create-namespace

echo -- провер€ем ingress поды
kubectl get pods -n ingress-nginx

echo -- смотрим ip кластера
minikube ip 

echo -- загружаем манифесты
kubectl apply -f run.yaml

echo -- metallb сетевой балансировщик, чтобы эмулировать туннелирование
minikube addons enable metallb
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.9.3/manifests/namespace.yaml
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.9.3/manifests/metallb.yaml

echo  запустили вебморду
minikube dashboard

